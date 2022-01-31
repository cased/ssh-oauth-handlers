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
	"path/filepath"
	"reflect"
	"runtime"
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
	"k8s.io/apimachinery/pkg/util/wait"
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
		http.Redirect(w, r, g.OAuthConfig.AuthCodeURL(sessionID, o2.AccessTypeOffline, o2.SetAuthURLParam("login_hint", email)), http.StatusFound)
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
	if stateToken != fmt.Sprintf("%s", session.Values["sessionID"]) {
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
	g.OAuth2TokenStore.Set(tokenInfo.Email, token)
	g.SessionEmails.Set(stateToken, tokenInfo.Email)
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

func (g *CloudShellSSHSessionOauthHandler) DefaultCommand() []string {
	return nil
}

func (g *CloudShellSSHSessionOauthHandler) SSHSessionCommandHandler(session ssh.Session, cmd *exec.Cmd) error {
	return errors.New("not implemented, Cloud Run can't run a modern shell")
}

func logAndPrintInternal(session ssh.Session, msg string, skip int) {
	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	msgWithSessionID := fmt.Sprintf("%s: "+msg, hex.EncodeToString(conn.SessionID()))
	_, file, no, ok := runtime.Caller(skip)
	if ok {
		log.Println(fmt.Sprintf("%s:%d: %s", filepath.Base(file), no, msgWithSessionID))
	} else {
		log.Println(msgWithSessionID)
	}
	io.WriteString(session, msgWithSessionID+"\n")
}

func logAndPrint(session ssh.Session, msg string) {
	logAndPrintInternal(session, msg, 2)
}

func logAndFail(session ssh.Session, msg string) {
	logAndPrintInternal(session, msg, 2)
	session.Exit(1)
}

func (g *CloudShellSSHSessionOauthHandler) SessionHandler(session ssh.Session) {
	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	sessionID := hex.EncodeToString(conn.SessionID())

	if session.Command() != nil {
		logAndFail(session, fmt.Sprintf("ignoring command: %s", session.Command()))
		return
	}

	cert, ok := session.PublicKey().(*gossh.Certificate)
	if !ok {
		logAndFail(session, "can't assert certificate")
		return
	}

	email := cert.ValidPrincipals[0]
	tokenSource := g.OAuth2TokenStore.Get(email)
	if tokenSource == nil {
		io.WriteString(session, g.authURLGenerator(sessionID)+"\n")
		err := wait.PollImmediate(1*time.Second, 45*time.Second, func() (bool, error) {
			tokenSource = g.OAuth2TokenStore.Get(email)
			if tokenSource == nil {
				io.WriteString(session, ".")
				return false, nil
			} else {
				logAndPrint(session, fmt.Sprintf("authorized as %s", email))
				return true, nil
			}
		})
		if err != nil {
			logAndFail(session, err.Error())
			return
		}
	}
	defer g.SessionEmails.Set(sessionID, "")

	cloudShellSession, err := NewCloudShellSession(session, tokenSource)
	if err != nil {
		logAndFail(session, err.Error())
		return
	}
	cloudShell, err := cloudShellSession.Connect()
	if err != nil {
		logAndFail(session, err.Error())
		return
	}
	defer cloudShell.Close()

	ptyReq, winCh, isPty := session.Pty()
	if !isPty {
		session.Exit(1)
		return
	}

	err = cloudShell.RequestPty(ptyReq.Term, ptyReq.Window.Width, ptyReq.Window.Height, gossh.TerminalModes{})
	if err != nil {
		logAndFail(session, err.Error())
		return
	}
	stdIn, err := cloudShell.StdinPipe()
	if err != nil {
		logAndFail(session, err.Error())
		return
	}
	defer stdIn.Close()

	stdOut, err := cloudShell.StdoutPipe()
	if err != nil {
		logAndFail(session, err.Error())
		return
	}

	stdErr, err := cloudShell.StderrPipe()
	if err != nil {
		logAndFail(session, err.Error())
		return
	}

	// Start remote shell
	if err := cloudShell.Shell(); err != nil {
		logAndFail(session, err.Error())
		return
	}

	go func() {
		err := cloudShell.WindowChange(ptyReq.Window.Width, ptyReq.Window.Width)
		io.WriteString(session, fmt.Sprintf("%s\n", err.Error()))
		for win := range winCh {
			err := cloudShell.WindowChange(win.Width, win.Height)
			io.WriteString(session, fmt.Sprintf("%s\n", err.Error()))
		}
	}()

	go func() {
		io.Copy(stdIn, session)
	}()
	go func() {
		io.Copy(session, stdOut)
	}()
	go func() {
		io.Copy(session.Stderr(), stdErr)
	}()

	err = cloudShell.Wait()

	// Pass along exit status
	if err != nil {
		log.Println(err.Error())
		if exitErr, ok := err.(*gossh.ExitError); ok {
			session.Exit(exitErr.ExitStatus())
		} else {
			session.Exit(1)
		}
	} else {
		session.Exit(0)
	}
}
