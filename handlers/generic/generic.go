package generic

import (
	"log"
	"net/http"
	"os/exec"

	"github.com/cased/ssh-oauth-handlers/partialauthhelper"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
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

func (h *GenericSSHHandler) KeyboardInteractiveHandler(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
	answers, err := challenger(ctx.User(), "http://example.com", []string{"Press enter once authentication completed"}, []bool{false})
	if len(answers) == 1 && answers[0] == "" && err == nil {
		helper := partialauthhelper.FromContext(ctx)
		helper.Satisfy(partialauthhelper.KeyboardInteractiveAuthMethod)
		return helper.Satisfied()
	} else {
		if err != nil {
			log.Printf("error obtaining answers: %v\n", err)
		}
		return false
	}
}
