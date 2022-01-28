package sshhandlers

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/cased/ssh-oauth-handlers/types"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"

	gossh "golang.org/x/crypto/ssh"
)

type CasedShellSSHHandler struct {
	ShellUrl string
}

func NewCasedShellSSHHandler(shellUrl string) *CasedShellSSHHandler {
	return &CasedShellSSHHandler{
		ShellUrl: shellUrl,
	}
}

func setWinsize(f *os.File, w, h int) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(h), uint16(w), 0, 0})))
}

func (h *CasedShellSSHHandler) casedShellIsUserAuthority(providedPubKey gossh.PublicKey) bool {
	resp, err := http.Get(fmt.Sprintf("%s/ca.pub", h.ShellUrl))
	if err != nil || resp.StatusCode != 200 {
		log.Println("error contacting shell")
		return false
	}
	authorizedKeyString, _ := io.ReadAll(resp.Body)
	authorizedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(authorizedKeyString))
	if err != nil {
		log.Println(fmt.Sprintf("Failed to parse ca.pub: %s %v", authorizedKeyString, err))
		return false
	}
	return bytes.Equal(providedPubKey.Marshal(), authorizedKey.Marshal())
}

func (h *CasedShellSSHHandler) CasedShellPublicKeyHandler(ctx ssh.Context, pubKey ssh.PublicKey) bool {
	sessionID := ctx.SessionID()
	cert, ok := pubKey.(*gossh.Certificate)
	if !ok {
		log.Printf("%s: normal key pairs not accepted\n", sessionID)
		return false
	}
	if cert.CertType != gossh.UserCert {
		log.Printf("%s: cert has type %d\n", sessionID, cert.CertType)
		return false
	}
	c := &gossh.CertChecker{
		IsUserAuthority: h.casedShellIsUserAuthority,
	}

	if !c.IsUserAuthority(cert.SignatureKey) {
		log.Printf("%s: certificate signed by unrecognized authority\n", sessionID)
		return false
	}

	resp, err := http.Get(fmt.Sprintf("%s/principal.txt", h.ShellUrl))
	if err != nil || resp.StatusCode != 200 {
		log.Printf("%s: error contacting shell\n", sessionID)
		return false
	}
	principal, _ := io.ReadAll(resp.Body)

	if err := c.CheckCert(string(principal), cert); err != nil {
		log.Printf("%s: %s not in list of valid principals %v\n", sessionID, string(principal), cert.ValidPrincipals)
		return false
	}

	if cert.Permissions.CriticalOptions["force-command"] != "" {
		log.Printf("%s: invalid force-command: %s\n", sessionID, cert.Permissions.CriticalOptions["force-command"])
		return false
	}

	log.Printf("%s: accepted SSH Certificate from %s\n", sessionID, cert.ValidPrincipals[0])

	return true
}

func failAndExit(s ssh.Session, err string) {
	log.Println(err)
	io.WriteString(s, err+"\n")
	s.Exit(1)
}

func (h *CasedShellSSHHandler) CasedShellSessionHandler(handler types.SSHSessionOauthHandler, command []string) ssh.Handler {
	if command == nil {
		return handler.SessionHandler
	}
	return func(s ssh.Session) {
		log.Printf("accepted connection for user %s\n", s.User())
		var args []string
		if len(s.Command()) > 0 {
			args = s.Command()
		} else {
			args = command
		}

		ptyReq, winCh, isPty := s.Pty()

		if isPty {
			var cmd *exec.Cmd
			if len(args) > 1 {
				cmd = exec.Command(args[0], args[1:]...)
			} else {
				cmd = exec.Command(args[0])
			}
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			cmd.Env = append(cmd.Env, "SHELL=/bin/bash")
			cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%s", os.Getenv("HOME")))
			err := handler.SSHSessionCommandHandler(s, cmd)
			if err != nil {
				failAndExit(s, err.Error())
				return
			}
			log.Println("starting session")
			f, err := pty.Start(cmd)
			if err != nil {
				failAndExit(s, err.Error())
				return
			}
			go func() {
				for win := range winCh {
					setWinsize(f, win.Width, win.Height)
				}
			}()
			go func() {
				io.Copy(f, s)
			}()
			io.Copy(s, f)
			cmd.Wait()
		} else {
			failAndExit(s, "no PTY requested")
			return
		}
	}
}
