package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cased/shell-util/oauth/heroku"
	"github.com/cased/shell-util/sshhandlers"
	"github.com/cased/shell-util/types"
	"github.com/gliderlabs/ssh"
)

var (
	command  = os.Args[0]
	provider = os.Args[1]
)

func main() {
	tokens := types.NewMemoryTokenStore()
	switch provider {
	case "heroku":
		http.HandleFunc("/oauth/auth", heroku.HandleAuth(tokens))
		http.HandleFunc("/oauth/auth/callback", heroku.HandleAuthCallback(tokens))
		http.HandleFunc("/oauth/user", heroku.HandleUser)
		go http.ListenAndServe(":2225", nil)
	default:
		usage()
	}

	s := &ssh.Server{
		Addr:                       ":2224",
		PublicKeyHandler:           sshhandlers.CasedShellPublicKeyHandler,
		IdleTimeout:                60 * time.Second,
		Version:                    "Cased Shell SSH",
		KeyboardInteractiveHandler: sshhandlers.CasedShellKeyboardInteractiveHandler(provider, tokens),
	}

	s.Handle(sshhandlers.CasedShellSessionHandler(tokens, []string{"bash", "-i"}, heroku.ConfigureCmdWithToken()))
	log.Println("starting ssh server on port 2224...")
	log.Fatal(s.ListenAndServe())
}

func usage() {
	log.Fatalf("%s is not a valid provider.\nUsage: %s heroku https://shell.example.com", provider, command)
}
