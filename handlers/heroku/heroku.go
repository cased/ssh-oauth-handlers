package heroku

import (
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"unsafe"

	"github.com/cased/shell-util/types"
	"github.com/gliderlabs/ssh"
	"github.com/gorilla/sessions"
	h5 "github.com/heroku/heroku-go/v5"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var (
	store       = sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET")), []byte(os.Getenv("COOKIE_ENCRYPT")))
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("OAUTH_ID"),
		ClientSecret: os.Getenv("OAUTH_SECRET"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://id.heroku.com/oauth/authorize",
			TokenURL: "https://id.heroku.com/oauth/token",
		},
		Scopes:      []string{"global"}, // See https://devcenter.heroku.com/articles/oauth#scopes
		RedirectURL: "https://" + os.Getenv("CASED_SHELL_HOSTNAME") + "/oauth/auth/callback"}
)

func init() {
	gob.Register(&oauth2.Token{})

	store.MaxAge(60 * 60 * 8)
}

type HerokuKeyboardInteractiveOAuthHandler struct {
	ShellUrl string
	Tokens   types.TokenStore
}

func NewHerokuKeyboardInteractiveOAuthHandler(shellUrl string) *HerokuKeyboardInteractiveOAuthHandler {
	return &HerokuKeyboardInteractiveOAuthHandler{
		ShellUrl: shellUrl,
		Tokens:   types.NewMemoryTokenStore(),
	}
}

func (h *HerokuKeyboardInteractiveOAuthHandler) AuthURLGenerator(ctx ssh.Context) string {
	return fmt.Sprintf("%s/oauth/stateToken=%s", h.ShellUrl, ctx.SessionID())
}

func (h *HerokuKeyboardInteractiveOAuthHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	stateToken := r.URL.Query().Get("stateToken")
	url := oauthConfig.AuthCodeURL(stateToken)
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

func (h *HerokuKeyboardInteractiveOAuthHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
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
	token, err := oauthConfig.Exchange(ctx, code)
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

func (h *HerokuKeyboardInteractiveOAuthHandler) HandleUser(w http.ResponseWriter, r *http.Request) {
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

func (h *HerokuKeyboardInteractiveOAuthHandler) HandleKeyboardInteractive() ssh.KeyboardInteractiveHandler {
	handler := func(ctx ssh.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
		answers, err := challenger("heroku", h.AuthURLGenerator(ctx), []string{"press enter to continue"}, []bool{false})
		if len(answers) == 1 && answers[0] == "" && err == nil {
			if h.Tokens.Get(ctx.SessionID()) == "" || h.Tokens.Get(ctx.SessionID()) == "pending" {
				return false
			} else {
				// we must have an actual token
				return true
			}
		} else {
			return false
		}
	}
	return handler
}

func getUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

func (h *HerokuKeyboardInteractiveOAuthHandler) HandleSessionCommand(session ssh.Session, cmd *exec.Cmd) error {
	conn := getUnexportedField(reflect.ValueOf(session).Elem().FieldByName("conn")).(*gossh.ServerConn)
	sessionID := hex.EncodeToString(conn.SessionID())
	var t string
	if h.Tokens.Get(sessionID) == "" || h.Tokens.Get(sessionID) == "pending" {
		return errors.New("can't find token")
	} else {
		t = h.Tokens.Get(sessionID)
	}
	if cmd == nil {
		return errors.New("cmd is nil")
	}
	cmd.Env = append(cmd.Env, "HEROKU_OAUTH_TOKEN="+t)
	return nil
}
