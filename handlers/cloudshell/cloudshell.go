package GCloud

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

type GCloudSSHSessionOauthHandler struct {
	DefaultCommand []string
	ShellUrl       string
	Tokens         types.TokenStore
	OAuthConfig    *o2.Config
}

func NewGCloudSSHSessionOauthHandler(shellUrl string, defaultCommand []string) *GCloudSSHSessionOauthHandler {

	return &GCloudSSHSessionOauthHandler{
		ShellUrl:       shellUrl,
		DefaultCommand: defaultCommand,
		Tokens:         types.NewMemoryTokenStore(),
		OAuthConfig: &o2.Config{
			ClientID:     os.Getenv("GCLOUD_OAUTH_CLIENT_ID"),
			ClientSecret: os.Getenv("GCLOUD_OAUTH_CLIENT_SECRET"),
			Endpoint:     google.Endpoint,
			Scopes:       []string{"email", "openid", "https://www.googleapis.com/auth/cloud-platform"},
			RedirectURL:  shellUrl + "/oauth/auth/callback",
		},
	}
}

func (g *GCloudSSHSessionOauthHandler) authURLGenerator(sessionID string) string {
	return fmt.Sprintf("%s/oauth/auth?stateToken=%s", g.ShellUrl, sessionID)
}

func (g *GCloudSSHSessionOauthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	stateToken := r.URL.Query().Get("stateToken")
	url := g.OAuthConfig.AuthCodeURL(stateToken)
	session, err := store.Get(r, "cased-shell-gcloud")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["stateToken"] = stateToken
	g.Tokens.Set(stateToken, "pending")
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (g *GCloudSSHSessionOauthHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
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
	if stateToken != fmt.Sprintf("%s", session.Values["stateToken"]) && g.Tokens.Get(stateToken) != "pending" {
		http.Error(w, "Invalid State token", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	token, err := g.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["gcloud-oauth-token"] = token
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/oauth/user", http.StatusFound)

}

func (g *GCloudSSHSessionOauthHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cased-shell-gcloud")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, ok := session.Values["gcloud-oauth-token"].(*o2.Token)
	if !ok {
		http.Error(w, "Unable to assert token", http.StatusInternalServerError)
		return
	}
	idTokenRaw := token.Extra("id_token")
	if idTokenRaw == nil {
		http.Error(w, "Unable to assert id_token", http.StatusInternalServerError)
		return
	}
	idToken, ok := idTokenRaw.(string)
	if !ok {
		http.Error(w, "Unable to coerce id_token", http.StatusInternalServerError)
		return
	}
	ctx := context.Background()
	oauth2Service, err := oauth2.NewService(ctx, option.WithTokenSource(g.OAuthConfig.TokenSource(ctx, token)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(idToken)
	tokenInfo, err := tokenInfoCall.Do()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	g.Tokens.Set(tokenInfo.Email, token.AccessToken)
	sessionId, ok := session.Values["stateToken"].(string)
	if !ok {
		http.Error(w, "Unable to determine sessionId", http.StatusInternalServerError)
		return
	}
	g.Tokens.Set(sessionId, tokenInfo.Email)
	fmt.Fprintf(w, `<html><body><p>Hi %s! You can close this window now, your shell should be ready.</p></body></html>`, tokenInfo.Email)
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

func (g *GCloudSSHSessionOauthHandler) validateCommand(cmd *exec.Cmd) error {
	log.Printf("validating command: %+v", cmd.Args)
	if cmd.Args[0] == "gcloud" {
		return nil
	}
	if Equal(cmd.Args, g.DefaultCommand) {
		return nil
	}
	return errors.New("command not recognized")
}

func (g *GCloudSSHSessionOauthHandler) SSHSessionCommandHandler(session ssh.Session, cmd *exec.Cmd) error {
	if err := g.validateCommand(cmd); err != nil {
		return err
	}

	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	sessionID := hex.EncodeToString(conn.SessionID())
	io.WriteString(session, "Login to GCloud: "+g.authURLGenerator(sessionID)+"\n")
	var accessToken string
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
			if g.Tokens.Get(sessionID) == "" || g.Tokens.Get(sessionID) == "pending" {
				return errors.New("timeout")
			}
		case <-ticker.C:
			if g.Tokens.Get(sessionID) != "" && g.Tokens.Get(sessionID) != "pending" {
				email := g.Tokens.Get(sessionID)
				accessToken = g.Tokens.Get(email)
				token := &o2.Token{
					AccessToken: accessToken,
				}
				io.WriteString(session, "done!\n")
				ctx := context.Background()
				c, err := shell.NewCloudShellClient(ctx, option.WithTokenSource(g.OAuthConfig.TokenSource(ctx, token)))
				if err != nil {
					return err
				}
				defer c.Close()

				req := &shellpb.GetEnvironmentRequest{
					Name: "users/me/environments/default",
				}
				resp, err := c.GetEnvironment(ctx, req)
				if err != nil {
					return err
				}
				// TODO connect to environment
				io.WriteString(session, fmt.Sprintf("%+v\n", resp))
				// clear token after using it
				g.Tokens.Set(sessionID, "")
				return nil
			} else {
				io.WriteString(session, ".")
			}

		}
	}
}
