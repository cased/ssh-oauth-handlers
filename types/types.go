package types

import (
	"context"
	"net/http"
	"os/exec"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
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
	// Return nil to call SessionHandler directly
	DefaultCommand() []string
	SSHSessionCommandHandler(ssh.Session, *exec.Cmd) error
	SessionHandler(ssh.Session)
	KeyboardInteractiveHandler(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool
}

type OAuth2TokenStore interface {
	SetOAuth2Config(*oauth2.Config)
	Set(string, *oauth2.Token)
	Get(string) oauth2.TokenSource
}

type MemoryOAuth2TokenStore struct {
	Tokens map[string]*oauth2.Token
	Config *oauth2.Config
}

func NewMemoryOAuth2TokenStore() *MemoryOAuth2TokenStore {
	return &MemoryOAuth2TokenStore{
		Tokens: make(map[string]*oauth2.Token),
	}
}

func (s *MemoryOAuth2TokenStore) SetOAuth2Config(config *oauth2.Config) {
	s.Config = config
}

func (s *MemoryOAuth2TokenStore) Set(key string, token *oauth2.Token) {
	s.Tokens[key] = token
}

func (s *MemoryOAuth2TokenStore) Get(key string) oauth2.TokenSource {
	current := s.Tokens[key]
	if current == nil {
		return nil
	}
	return s.Config.TokenSource(context.Background(), current)
}
