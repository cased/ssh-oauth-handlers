package publickeyhandler

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/cased/ssh-oauth-handlers/partialauthhelper"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

var (
	shellUrl = os.Args[2]
)

func casedShellIsUserAuthority(providedPubKey gossh.PublicKey) bool {
	resp, err := http.Get(fmt.Sprintf("%s/ca.pub", shellUrl))
	if err != nil || resp.StatusCode != 200 {
		log.Println(fmt.Sprintf("error contacting shell: %v", err))
		return false
	}
	authorizedKeyString, _ := io.ReadAll(resp.Body)
	authorizedKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(authorizedKeyString))
	if err != nil {
		log.Println(fmt.Sprintf("Failed to parse ca.pub: %s %v", authorizedKeyString, err))
		return false
	}
	return bytes.Equal(providedPubKey.Marshal(), authorizedKey.Marshal())
}

func Handler(ctx ssh.Context, pubKey ssh.PublicKey) (result bool) {
	helper := partialauthhelper.FromContext(ctx)
	if helper.MethodSatisfied(partialauthhelper.PublicKeyAuthMethod) {
		return true
	}
	result = handle(ctx, pubKey)
	if result {
		helper.Satisfy(partialauthhelper.PublicKeyAuthMethod)
	}
	return helper.Satified()
}

func handle(ctx ssh.Context, pubKey ssh.PublicKey) bool {
	ctx.SetValue("user", ctx.User())
	sessionID := ctx.SessionID()
	cert, ok := pubKey.(*gossh.Certificate)
	if !ok {
		log.Printf("%s: normal key pairs not accepted\n", sessionID)
		return false
	}
	if cert.CertType != gossh.UserCert {
		log.Printf("%s: cert has type %d\n", sessionID, cert.CertType)
		return false
	}
	c := &gossh.CertChecker{
		IsUserAuthority: casedShellIsUserAuthority,
	}

	if !c.IsUserAuthority(cert.SignatureKey) {
		log.Printf("%s: certificate signed by unrecognized authority\n", sessionID)
		return false
	}

	resp, err := http.Get(fmt.Sprintf("%s/principal.txt", shellUrl))
	if err != nil || resp.StatusCode != 200 {
		log.Println(fmt.Sprintf("error contacting shell: %v", err))
		return false
	}
	principal, _ := io.ReadAll(resp.Body)

	if err := c.CheckCert(string(principal), cert); err != nil {
		log.Printf("%s: %s not in list of valid principals %v\n", sessionID, string(principal), cert.ValidPrincipals)
		return false
	}

	if cert.Permissions.CriticalOptions["force-command"] != "" {
		log.Printf("%s: invalid force-command: %s\n", sessionID, cert.Permissions.CriticalOptions["force-command"])
		return false
	}

	log.Printf("%s: accepted SSH Certificate from %s\n", sessionID, cert.ValidPrincipals[0])

	return true
}
