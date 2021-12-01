package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cased/ssh-oauth-handlers/handlers/heroku"
	"github.com/cased/ssh-oauth-handlers/sshhandlers"
	"github.com/cased/ssh-oauth-handlers/types"
	"github.com/gliderlabs/ssh"
	"github.com/soheilhy/cmux"
)

var (
	command  = os.Args[0]
	provider = os.Args[1]
	shellUrl = os.Args[2]
	cmd      = os.Args[3:]
)

func main() {
	if len(os.Args) < 4 {
		usage()
	}
	var handler types.SSHSessionOauthHandler
	switch provider {
	case "heroku":
		handler = heroku.NewHerokuSSHSessionOauthHandler(shellUrl)
	default:
		usage()
	}

	http.HandleFunc("/oauth/auth", handler.HandleAuth)
	http.HandleFunc("/oauth/auth/callback", handler.HandleAuthCallback)
	http.HandleFunc("/oauth/user", handler.HandleUser)

	sshHandler := sshhandlers.NewCasedShellSSHHandler(shellUrl)

	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "2225"
	}

	sshServer := &ssh.Server{
		Addr:             ":" + port,
		PublicKeyHandler: sshHandler.CasedShellPublicKeyHandler,
		IdleTimeout:      60 * time.Second,
		Version:          "Cased Shell + " + provider,
	}
	sshServer.Handle(sshHandler.CasedShellSessionHandler(handler, cmd))

	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	m := cmux.New(l)
	httpL := m.Match(cmux.HTTP1Fast())
	// httpsL := m.Match(cmux.TLS())
	sshL := m.Match(cmux.Any())

	go http.Serve(httpL, nil)
	go sshServer.Serve(sshL)
	log.Printf("Listening on :%s\n", port)
	m.Serve()
}

func usage() {
	log.Fatalf("\nUsage: %s heroku https://shell.example.com bash -i", command)
}
