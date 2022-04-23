package partialauthhelper

import (
	"reflect"
	"sort"

	"github.com/gliderlabs/ssh"
)

const (
	KeyboardInteractiveAuthMethod         = "keyboard-interactive"
	PublicKeyAuthMethod                   = "public-key"
	PartialSuccessContextKey              = "PartialSuccess"
	PartialAuthenticationHelperContextKey = "PartialAuthenticationHelper"
)

type PartialAuthenticationHelper struct {
	RequiredMethods  []string
	satisfiedMethods []string
}

func AddToContext(ctx ssh.Context) {
	p := &PartialAuthenticationHelper{
		RequiredMethods: []string{KeyboardInteractiveAuthMethod, PublicKeyAuthMethod},
	}
	ctx.SetValue(PartialAuthenticationHelperContextKey, p)
}

func FromContext(ctx ssh.Context) *PartialAuthenticationHelper {
	return ctx.Value(PartialAuthenticationHelperContextKey).(*PartialAuthenticationHelper)
}

func (t *PartialAuthenticationHelper) Satisfy(method string) {
	for _, a := range t.satisfiedMethods {
		if a == method {
			return
		}
	}
	t.satisfiedMethods = append(t.satisfiedMethods, method)
}

func (t *PartialAuthenticationHelper) Satified() bool {
	sort.Strings(t.RequiredMethods)
	sort.Strings(t.satisfiedMethods)
	return reflect.DeepEqual(t.RequiredMethods, t.satisfiedMethods)
}

func (t *PartialAuthenticationHelper) MethodSatisfied(method string) bool {
	for _, a := range t.satisfiedMethods {
		if a == method {
			return true
		}
	}
	return false
}
