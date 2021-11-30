package types

import (
	"net/http"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

type TokenStore interface {
	Get(sessionID string) string
	Set(sessionID, value string)
}

type CmdTokenConfigurator func(*exec.Cmd, string) error

type MemoryTokenStore struct {
	Tokens map[string]string
}

func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{
		Tokens: make(map[string]string),
	}
}

func (s *MemoryTokenStore) Get(sessionID string) string {
	return s.Tokens[sessionID]
}

func (s *MemoryTokenStore) Set(sessionID, value string) {
	s.Tokens[sessionID] = value
}

type KeyboardInteractiveOAuthHandler interface {
	AuthURLGenerator(ctx ssh.Context) string
	HandleAuth(w http.ResponseWriter, r *http.Request)
	HandleAuthCallback(w http.ResponseWriter, r *http.Request)
	HandleUser(w http.ResponseWriter, r *http.Request)
	HandleKeyboardInteractive() ssh.KeyboardInteractiveHandler
	HandleSessionCommand(ssh.Session, *exec.Cmd) error
}
