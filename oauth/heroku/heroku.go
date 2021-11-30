package heroku

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/cased/shell-util/types"
	"github.com/gorilla/sessions"
	heroku "github.com/heroku/heroku-go/v5"
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

func ConfigureCmdWithToken() func(cmd *exec.Cmd, token string) error {
	return func(cmd *exec.Cmd, token string) error {
		cmd.Env = append(cmd.Env, fmt.Sprintf("HEROKU_API_KEY=%s", token))
		return nil
	}
}

func HandleAuth(tokens types.TokenStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		stateToken := r.URL.Query().Get("stateToken")
		url := oauthConfig.AuthCodeURL(stateToken)
		session, err := store.Get(r, "cased-shell-heroku")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["stateToken"] = stateToken
		tokens.Set(stateToken, "pending")
		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func HandleAuthCallback(tokens types.TokenStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if stateToken != fmt.Sprintf("%s", session.Values["stateToken"]) && tokens.Get(stateToken) != "pending" {
			http.Error(w, "Invalid State token", http.StatusBadRequest)
			return
		}
		ctx := context.Background()
		token, err := oauthConfig.Exchange(ctx, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tokens.Set(stateToken, token.AccessToken)
		session.Values["heroku-oauth-token"] = token
		if err := session.Save(r, w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/oauth/user", http.StatusFound)
	}
}

func HandleUser(w http.ResponseWriter, r *http.Request) {
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
		Transport: &heroku.Transport{
			BearerToken: token.AccessToken,
		},
	}
	h := heroku.NewService(herokuClient)
	account, err := h.AccountInfo(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, `<html><body><p>Hi %s! You can close this window now, your shell should be ready.</p></body></html>`, account.Email)
}
