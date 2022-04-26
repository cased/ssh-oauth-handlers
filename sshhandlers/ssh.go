package sshhandlers

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/cased/ssh-oauth-handlers/types"
	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
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

func failAndExit(s ssh.Session, err string) {
	log.Println(err)
	io.WriteString(s, err+"\n")
	s.Exit(1)
}

func (h *CasedShellSSHHandler) CasedShellSessionHandler(handler types.SSHSessionOauthHandler) ssh.Handler {
	if handler.DefaultCommand() == nil {
		return handler.SessionHandler
	}
	return func(s ssh.Session) {
		log.Printf("accepted connection for user %s\n", s.User())
		var args []string
		if len(s.Command()) > 0 {
			args = s.Command()
		} else {
			args = handler.DefaultCommand()
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
