package generic

import (
	"net/http"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

type GenericSSHHandler struct {
	defaultCommand []string
	ShellUrl       string
}

func NewGenericSSHHandler(shellUrl string, defaultCommand []string) *GenericSSHHandler {
	return &GenericSSHHandler{
		ShellUrl:       shellUrl,
		defaultCommand: defaultCommand,
	}
}

func (h *GenericSSHHandler) DefaultCommand() []string {
	return h.defaultCommand
}

func (h *GenericSSHHandler) SessionHandler(session ssh.Session) {
	// noop
}

func (h *GenericSSHHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusInternalServerError)
}

func (h *GenericSSHHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusInternalServerError)
}

func (h *GenericSSHHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented", http.StatusInternalServerError)
}

func (h *GenericSSHHandler) SSHSessionCommandHandler(session ssh.Session, cmd *exec.Cmd) error {
	return nil
}
