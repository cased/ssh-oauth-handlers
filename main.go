package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cased/ssh-oauth-handlers/handlers/cloudshell"
	"github.com/cased/ssh-oauth-handlers/handlers/generic"
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
	var oauthHandler types.SSHSessionOauthHandler
	switch provider {
	case "heroku":
		oauthHandler = heroku.NewHerokuSSHSessionOauthHandler(shellUrl, cmd)
	case "generic":
		oauthHandler = generic.NewGenericSSHHandler(shellUrl, cmd)
	case "cloudshell":
		// cloudshell ignores any set default command
		oauthHandler = cloudshell.NewCloudShellSSHSessionOauthHandler(shellUrl, nil)
	default:
		usage()
	}

	http.HandleFunc("/oauth/auth", oauthHandler.HandleAuth)
	http.HandleFunc("/oauth/auth/callback", oauthHandler.HandleAuthCallback)
	http.HandleFunc("/oauth/user", oauthHandler.HandleUser)

	sshHandler := sshhandlers.NewCasedShellSSHHandler(shellUrl)

	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "2225"
	}

	var kbd ssh.KeyboardInteractiveHandler
	if os.Getenv("KBD") == "true" {
		kbd = oauthHandler.KeyboardInteractiveHandler
	}

	sshServer := &ssh.Server{
		Addr:                       ":" + port,
		PublicKeyHandler:           sshHandler.CasedShellPublicKeyHandler,
		KeyboardInteractiveHandler: kbd,
		IdleTimeout:                60 * time.Second,
		Version:                    "Cased Shell + " + provider,
	}
	sshServer.Handle(sshHandler.CasedShellSessionHandler(oauthHandler))

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
	log.Fatalf("\nUsage: %s <provider> <shell_url> <default command to run for new sessions>", command)
}
