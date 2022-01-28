package heroku

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
	h5 "github.com/heroku/heroku-go/v5"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var (
	store = sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET")), []byte(os.Getenv("COOKIE_ENCRYPT")))
)

func init() {
	gob.Register(&oauth2.Token{})

	store.MaxAge(60 * 60 * 8)
}

type HerokuSSHSessionOauthHandler struct {
	DefaultCommand []string
	ShellUrl       string
	Tokens         types.TokenStore
	OAuthConfig    *oauth2.Config
}

func NewHerokuSSHSessionOauthHandler(shellUrl string, defaultCommand []string) *HerokuSSHSessionOauthHandler {
	return &HerokuSSHSessionOauthHandler{
		ShellUrl:       shellUrl,
		DefaultCommand: defaultCommand,
		Tokens:         types.NewMemoryTokenStore(),
		OAuthConfig: &oauth2.Config{
			ClientID:     os.Getenv("HEROKU_OAUTH_ID"),
			ClientSecret: os.Getenv("HEROKU_OAUTH_SECRET"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://id.heroku.com/oauth/authorize",
				TokenURL: "https://id.heroku.com/oauth/token",
			},
			Scopes:      []string{"global"}, // See https://devcenter.heroku.com/articles/oauth#scopes
			RedirectURL: shellUrl + "/oauth/auth/callback",
		},
	}
}

func (h *HerokuSSHSessionOauthHandler) authURLGenerator(sessionID string) string {
	return fmt.Sprintf("%s/oauth/auth?stateToken=%s", h.ShellUrl, sessionID)
}

func (h *HerokuSSHSessionOauthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	stateToken := r.URL.Query().Get("stateToken")
	url := h.OAuthConfig.AuthCodeURL(stateToken)
	session, err := store.Get(r, "cased-shell-heroku")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["stateToken"] = stateToken
	h.Tokens.Set(stateToken, "pending")
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *HerokuSSHSessionOauthHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cased-shell-heroku")
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
	if stateToken != fmt.Sprintf("%s", session.Values["stateToken"]) && h.Tokens.Get(stateToken) != "pending" {
		http.Error(w, "Invalid State token", http.StatusBadRequest)
		return
	}
	ctx := context.Background()
	token, err := h.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Tokens.Set(stateToken, token.AccessToken)
	session.Values["heroku-oauth-token"] = token
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/oauth/user", http.StatusFound)

}

func (h *HerokuSSHSessionOauthHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "cased-shell-heroku")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	token, ok := session.Values["heroku-oauth-token"].(*oauth2.Token)
	if !ok {
		http.Error(w, "Unable to assert token", http.StatusInternalServerError)
		return
	}
	herokuClient := &http.Client{
		Transport: &h5.Transport{
			BearerToken: token.AccessToken,
		},
	}
	herokuService := h5.NewService(herokuClient)
	account, err := herokuService.AccountInfo(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, `<html><body><p>Hi %s! You can close this window now, your shell should be ready.</p></body></html>`, account.Email)
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

func (h *HerokuSSHSessionOauthHandler) validateCommand(cmd *exec.Cmd) error {
	log.Printf("validating command: %+v", cmd.Args)
	if cmd.Args[0] == "heroku" {
		return nil
	}
	if Equal(cmd.Args, h.DefaultCommand) {
		return nil
	}
	return errors.New("command not recognized")
}

func (h *HerokuSSHSessionOauthHandler) SessionHandler(session ssh.Session) {
	// noop
}

func (h *HerokuSSHSessionOauthHandler) SSHSessionCommandHandler(session ssh.Session, cmd *exec.Cmd) error {
	if err := h.validateCommand(cmd); err != nil {
		return err
	}

	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	sessionID := hex.EncodeToString(conn.SessionID())
	io.WriteString(session, "Login to Heroku: "+h.authURLGenerator(sessionID))
	io.WriteString(session, "\nWaiting for token...")
	var token string
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
			if h.Tokens.Get(sessionID) == "" || h.Tokens.Get(sessionID) == "pending" {
				return errors.New("timeout")
			}
		case <-ticker.C:
			if h.Tokens.Get(sessionID) != "" && h.Tokens.Get(sessionID) != "pending" {
				token = h.Tokens.Get(sessionID)
				io.WriteString(session, "done!\n")
				cmd.Env = append(cmd.Env, "HEROKU_API_KEY="+token)
				// clear token after copying it to the environment
				h.Tokens.Set(sessionID, "")
				return nil
			} else {
				io.WriteString(session, ".")
			}

		}
	}
}
