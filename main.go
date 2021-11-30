package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cased/shell-util/handlers/heroku"
	"github.com/cased/shell-util/sshhandlers"
	"github.com/cased/shell-util/types"
	"github.com/gliderlabs/ssh"
)

var (
	command  = os.Args[0]
	provider = os.Args[1]
	shellUrl = os.Args[2]
	cmd      = os.Args[3:]
)

func main() {
	var handler types.KeyboardInteractiveOAuthHandler
	switch provider {
	case "heroku":
		handler = heroku.NewHerokuKeyboardInteractiveOAuthHandler(shellUrl)
	default:
		usage()
	}

	http.HandleFunc("/oauth/auth", handler.HandleAuth)
	http.HandleFunc("/oauth/auth/callback", handler.HandleAuthCallback)
	http.HandleFunc("/oauth/user", handler.HandleUser)
	go http.ListenAndServe(":2225", nil)

	sshHandler := sshhandlers.NewCasedShellSSHHandler(shellUrl)

	s := &ssh.Server{
		Addr:                       ":2224",
		PublicKeyHandler:           sshHandler.CasedShellPublicKeyHandler,
		IdleTimeout:                60 * time.Second,
		Version:                    "Cased Shell SSH",
		KeyboardInteractiveHandler: handler.HandleKeyboardInteractive(),
	}

	s.Handle(sshHandler.CasedShellSessionHandler(handler, cmd))
	log.Println("starting ssh server on port 2224...")
	log.Fatal(s.ListenAndServe())
}

func usage() {
	log.Fatalf("\nUsage: %s heroku https://shell.example.com bash -i", command)
}
