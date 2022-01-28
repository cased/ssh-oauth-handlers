package cloudshell

import (
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"time"
	"unsafe"

	"github.com/cased/ssh-oauth-handlers/types"
	"github.com/gliderlabs/ssh"
	"github.com/gorilla/sessions"
	gossh "golang.org/x/crypto/ssh"
	o2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	shell "cloud.google.com/go/shell/apiv1"
	shellpb "google.golang.org/genproto/googleapis/cloud/shell/v1"
)

var (
	store = sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET")), []byte(os.Getenv("COOKIE_ENCRYPT")))
)

func init() {
	gob.Register(&o2.Token{})

	store.MaxAge(60 * 60 * 8)
}

type CloudShellSSHSessionOauthHandler struct {
	ShellUrl         string
	OAuthConfig      *o2.Config
	OAuth2TokenStore types.OAuth2TokenStore
	SessionEmails    types.TokenStore
}

func NewCloudShellSSHSessionOauthHandler(shellUrl string, defaultCommand []string) *CloudShellSSHSessionOauthHandler {
	config := &o2.Config{
		ClientID:     os.Getenv("GCLOUD_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GCLOUD_OAUTH_CLIENT_SECRET"),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"email", "openid", "https://www.googleapis.com/auth/cloud-platform"},
		RedirectURL:  shellUrl + "/oauth/auth/callback",
	}
	tokenStore := types.NewMemoryOAuth2TokenStore()
	tokenStore.SetOAuth2Config(config)
	return &CloudShellSSHSessionOauthHandler{
		ShellUrl:         shellUrl,
		OAuthConfig:      config,
		OAuth2TokenStore: tokenStore,
		SessionEmails:    types.NewMemoryTokenStore(),
	}
}

func (g *CloudShellSSHSessionOauthHandler) authURLGenerator(sessionID string) string {
	return fmt.Sprintf("%s/oauth/auth?stateToken=%s", g.ShellUrl, sessionID)
}

func (g *CloudShellSSHSessionOauthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("stateToken")
	session, err := store.Get(r, "cased-shell-gcloud")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["sessionID"] = sessionID
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	email, ok := session.Values["email"].(string)
	if !ok || email == "" {
		http.Redirect(w, r, g.OAuthConfig.AuthCodeURL(sessionID, o2.AccessTypeOffline), http.StatusFound)
		return
	}
	tokenSource := g.OAuth2TokenStore.Get(email)
	if tokenSource == nil {
		http.Redirect(w, r, g.OAuthConfig.AuthCodeURL(sessionID, o2.AccessTypeOffline), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/oauth/user", http.StatusFound)
}

func tokenToIDToken(token *o2.Token) (string, error) {
	idTokenRaw := token.Extra("id_token")
	if idTokenRaw == nil {
		return "", errors.New("unable to assert id_token")
	}
	idToken, ok := idTokenRaw.(string)
	if !ok {
		return "", errors.New("unable to coerce id_token")
	}
	return idToken, nil
}

func (g *CloudShellSSHSessionOauthHandler) getTokenInfo(token *o2.Token) (*oauth2.Tokeninfo, error) {
	ctx := context.Background()
	oauth2Service, err := oauth2.NewService(ctx, option.WithTokenSource(g.OAuthConfig.TokenSource(ctx, token)))
	if err != nil {
		return nil, err
	}

	idToken, err := tokenToIDToken(token)
	if err != nil {
		return nil, err
	}

	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(idToken)
	tokenInfo, err := tokenInfoCall.Do()

	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func (g *CloudShellSSHSessionOauthHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cased-shell-gcloud")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stateToken := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, r.URL.RequestURI(), http.StatusBadRequest)
		return
	}
	if stateToken != fmt.Sprintf("%s", session.Values["sessionID"]) && g.SessionEmails.Get(stateToken) != "" {
		http.Error(w, "Invalid State token", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	token, err := g.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tokenInfo, err := g.getTokenInfo(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	g.SessionEmails.Set(stateToken, tokenInfo.Email)
	g.OAuth2TokenStore.Set(tokenInfo.Email, token)
	session.Values["email"] = tokenInfo.Email
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/oauth/user", http.StatusFound)
}

func (g *CloudShellSSHSessionOauthHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cased-shell-gcloud")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	email, ok := session.Values["email"].(string)
	if !ok {
		http.Error(w, "couldn't load account from session", http.StatusInternalServerError)
		return
	}
	// TODO validate access to Cloudshell API here
	fmt.Fprintf(w, `<html><body><p>Hi %s! You can close this window now, your shell should be ready.</p></body></html>`, email)
}

func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (g *CloudShellSSHSessionOauthHandler) tokenSourceForSession(sessionID string) o2.TokenSource {
	email := g.SessionEmails.Get(sessionID)
	return g.OAuth2TokenStore.Get(email)
}

func (g *CloudShellSSHSessionOauthHandler) DefaultCommand() []string {
	return nil
}

func (g *CloudShellSSHSessionOauthHandler) SSHSessionCommandHandler(session ssh.Session, cmd *exec.Cmd) error {
	return errors.New("not implemented, Cloud Run can't run a modern shell")
}

func (g *CloudShellSSHSessionOauthHandler) SessionHandler(session ssh.Session) {
	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	sessionID := hex.EncodeToString(conn.SessionID())

	_, winCh, isPty := session.Pty()

	if !isPty {
		session.Exit(1)
		return
	}
	go func() {
		for win := range winCh {
			log.Printf("%s: ignoring window change: %+v\n", sessionID, win)
		}
	}()

	cert, ok := session.PublicKey().(*gossh.Certificate)
	if !ok {
		io.WriteString(session, fmt.Sprintf("%s: normal key pairs not accepted\n", sessionID))
		session.Exit(1)
		return
	}
	io.WriteString(session, fmt.Sprintf("%s: Greetings %s\n", sessionID, cert.ValidPrincipals[0]))
	io.WriteString(session, fmt.Sprintf("%s: Cert details %+v\n", sessionID, cert))
	io.WriteString(session, fmt.Sprintf("%s: Login to GCloud: %s\n ", sessionID, g.authURLGenerator(sessionID)))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func() {
		time.Sleep(45 * time.Second)
		done <- true
	}()
	for {
		select {
		case <-done:
			if g.SessionEmails.Get(sessionID) == "" {
				io.WriteString(session, "timeout")
				session.Exit(1)
				return
			}
		case <-ticker.C:
			if g.SessionEmails.Get(sessionID) != "" {
				io.WriteString(session, "done!\n")
				ctx := context.Background()
				c, err := shell.NewCloudShellClient(ctx, option.WithTokenSource(g.tokenSourceForSession(sessionID)))
				if err != nil {
					io.WriteString(session, err.Error())
					session.Exit(1)
					return
				}
				defer c.Close()

				req := &shellpb.GetEnvironmentRequest{
					Name: "users/me/environments/default",
				}
				resp, err := c.GetEnvironment(ctx, req)
				if err != nil {
					io.WriteString(session, err.Error())
					session.Exit(1)
					return
				}
				// TODO connect to environment
				io.WriteString(session, fmt.Sprintf("%+v\n", resp))
				// ensure session is marked as closed
				g.SessionEmails.Set(sessionID, "")
				session.Exit(0)
			} else {
				io.WriteString(session, ".")
			}

		}
	}
}
