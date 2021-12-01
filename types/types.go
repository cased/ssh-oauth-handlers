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

type SSHSessionOauthHandler interface {
	HandleAuth(w http.ResponseWriter, r *http.Request)
	HandleAuthCallback(w http.ResponseWriter, r *http.Request)
	HandleUser(w http.ResponseWriter, r *http.Request)
	SSHSessionCommandHandler(ssh.Session, *exec.Cmd) error
}
