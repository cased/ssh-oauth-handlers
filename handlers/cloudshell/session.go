package cloudshell

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	shell "cloud.google.com/go/shell/apiv1"
	"github.com/gliderlabs/ssh"
	"github.com/hashicorp/go-multierror"
	gossh "golang.org/x/crypto/ssh"
	o2 "golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	shellpb "google.golang.org/genproto/googleapis/cloud/shell/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type CloudShellSession interface {
	Close() error
	Connect() (*gossh.Session, error)
}

type cloudShellSession struct {
	casedShellSession ssh.Session
	cloudShellSession *gossh.Session
	cloudShellClient  *shell.CloudShellClient
	cloudShell        *shellpb.Environment
	tokenSource       o2.TokenSource
	publicKey         string
	privateKey        string
	ctx               context.Context
}

func NewCloudShellSession(casedShellSession ssh.Session, tokenSource o2.TokenSource) (CloudShellSession, error) {
	cs := &cloudShellSession{
		casedShellSession: casedShellSession,
		ctx:               context.Background(),
		tokenSource:       tokenSource,
	}

	pub, priv, err := genKeyPair()
	if err != nil {
		return nil, fmt.Errorf("couldn't generate keypair: %w", err)
	}
	cs.publicKey = pub
	cs.privateKey = priv

	c, err := shell.NewCloudShellClient(cs.ctx, option.WithTokenSource(cs.tokenSource))
	if err != nil {
		return nil, fmt.Errorf("couldn't prepare CloudShell client: %w", err)
	}
	cs.cloudShellClient = c
	return cs, nil
}

func (css *cloudShellSession) Connect() (*gossh.Session, error) {
	cloudShell, err := css.preparedCloudShell()
	if err != nil {
		return nil, fmt.Errorf("couldn't prepare CloudShell: %w", err)
	}
	key, err := gossh.ParsePrivateKey([]byte(css.privateKey))
	if err != nil {
		return nil, fmt.Errorf("couldn't parse private key: %w", err)
	}

	user, host, port := cloudShell.SshUsername, cloudShell.SshHost, cloudShell.SshPort
	config := &gossh.ClientConfig{
		User: user,
		// HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(key),
		},
	}
	// TODO keepalives
	netloc := net.JoinHostPort(host, string(port))
	client, err := gossh.Dial("tcp", netloc, config)
	if err != nil {
		return nil, fmt.Errorf("couldn't connect to %s: %w", netloc, err)
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("couldn't establish ssh session after connecting to %s: %w", netloc, err)
	}
	css.cloudShellSession = session
	return css.cloudShellSession, nil
}

func (css *cloudShellSession) preparedCloudShell() (*shellpb.Environment, error) {
	var err error
	css.cloudShell, err = css.cloudShellClient.GetEnvironment(css.ctx, &shellpb.GetEnvironmentRequest{
		Name: "users/me/environments/default",
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't read environment: %w", err)
	}
	token, err := css.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("couldn't obtain token: %w", err)
	}
	if css.cloudShell.State != shellpb.Environment_RUNNING {
		req := &shellpb.StartEnvironmentRequest{
			Name: css.cloudShell.Name,
		}
		op, err := css.cloudShellClient.StartEnvironment(css.ctx, req)
		if err != nil {
			if e, ok := err.(*googleapi.Error); ok {
				return nil, fmt.Errorf("couldn't StartEnvironment (%+v): %+v: %w", req, e, err)
			} else {
				return nil, fmt.Errorf("couldn't StartEnvironment (%+v): %w", req, err)
			}
		}
		resp, err := op.Wait(css.ctx)
		if err != nil {
			return nil, fmt.Errorf("couldn't refresh op: %w", err)
		}
		css.cloudShell = resp.GetEnvironment()
	}
	{
		req := &shellpb.AddPublicKeyRequest{
			Environment: css.cloudShell.Name,
			Key:         css.publicKey,
		}

		op, err := css.cloudShellClient.AddPublicKey(css.ctx, req)
		if err != nil {
			if e, ok := err.(*googleapi.Error); ok {
				return nil, fmt.Errorf("couldn't AddPublicKey (%+v): %+v: %w", req, e, err)
			} else {
				return nil, fmt.Errorf("couldn't AddPublicKey (%+v): %w", req, err)
			}
		}
		_, err = op.Wait(css.ctx)
		if err != nil {
			return nil, fmt.Errorf("couldn't refresh op: %w", err)
		}
	}
	{
		req := &shellpb.AuthorizeEnvironmentRequest{
			Name:        css.cloudShell.Name,
			AccessToken: token.AccessToken,
			IdToken:     token.Extra("id_token").(string),
			ExpireTime:  timestamppb.New(token.Expiry),
		}
		op, err := css.cloudShellClient.AuthorizeEnvironment(css.ctx, req)
		if err != nil {
			if e, ok := err.(*googleapi.Error); ok {
				return nil, fmt.Errorf("couldn't AuthorizeEnvironment (%+v): %+v: %w", req, e, err)
			} else {
				return nil, fmt.Errorf("couldn't AuthorizeEnvironment (%+v): %w", req, err)
			}
		}
		_, err = op.Wait(css.ctx)
		if err != nil {
			return nil, fmt.Errorf("couldn't refresh op: %w", err)
		}
	}

	css.cloudShell, err = css.cloudShellClient.GetEnvironment(css.ctx, &shellpb.GetEnvironmentRequest{
		Name: css.cloudShell.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't read environment: %w", err)
	}
	return css.cloudShell, nil
}

func (css *cloudShellSession) Close() (errs error) {
	if css.cloudShellSession != nil {
		err := css.cloudShellSession.Close()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	if css.cloudShellClient != nil {
		err := css.cloudShellClient.Close()
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

func genKeyPair() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	var private bytes.Buffer
	if err := pem.Encode(&private, block); err != nil {
		return "", "", err
	}

	pub, err := gossh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}

	public := gossh.MarshalAuthorizedKey(pub)
	return strings.TrimSuffix(string(public), "\n"), private.String(), nil
}
