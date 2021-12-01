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
	cert, ok := pubKey.(*gossh.Certificate)
	if !ok {
		log.Println("normal key pairs not accepted")
		return false
	}
	if cert.CertType != gossh.UserCert {
		log.Printf("cert has type %d\n", cert.CertType)
		return false
	}
	c := &gossh.CertChecker{
		IsUserAuthority: h.casedShellIsUserAuthority,
	}

	if !c.IsUserAuthority(cert.SignatureKey) {
		log.Println("certificate signed by unrecognized authority")
		return false
	}

	resp, err := http.Get(fmt.Sprintf("%s/principal.txt", h.ShellUrl))
	if err != nil || resp.StatusCode != 200 {
		log.Println("error contacting shell")
		return false
	}
	principal, _ := io.ReadAll(resp.Body)

	if err := c.CheckCert(string(principal), cert); err != nil {
		log.Printf("%s not in list of valid principals %v\n", string(principal), cert.ValidPrincipals)
		return false
	}

	if cert.Permissions.CriticalOptions["force-command"] != "" {
		log.Printf("invalid force-command: %s\n", cert.Permissions.CriticalOptions["force-command"])
		return false
	}

	log.Printf("accepted SSH Certificate from %s\n", cert.ValidPrincipals[0])

	return true
}

func failAndExit(s ssh.Session, err string) {
	log.Println(err)
	io.WriteString(s, err+"\n")
	s.Exit(1)
}

func (h *CasedShellSSHHandler) CasedShellSessionHandler(handler types.SSHSessionOauthHandler, command []string) ssh.Handler {
	return func(s ssh.Session) {
		log.Printf("accepted connection for user %s\n", s.User())
		if len(s.Command()) > 0 {
			failAndExit(s, "command execution not supported")
			return
		}

		ptyReq, winCh, isPty := s.Pty()

		if isPty {
			cmd := exec.Command(command[0], command[1:]...)
			cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
			cmd.Env = append(cmd.Env, "SHELL=/bin/bash")
			cmd.Env = append(cmd.Env, fmt.Sprintf("HOME=%s", os.Getenv("HOME")))
			err := handler.SSHSessionCommandHandler(s, cmd)
			if err != nil {
				failAndExit(s, "error configuring command with token")
				return
			}
			f, err := pty.Start(cmd)
			if err != nil {
				failAndExit(s, "error starting PTY")
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
