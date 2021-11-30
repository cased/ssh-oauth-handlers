package types

import (
	"os/exec"
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
