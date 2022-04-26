package partialauthhelper

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/gliderlabs/ssh"
)

const (
	KeyboardInteractiveAuthMethod         string = "keyboard-interactive"
	PublicKeyAuthMethod                   string = "public-key"
	PartialAuthenticationHelperContextKey string = "PartialAuthenticationHelper"
)

type PartialAuthenticationHelper struct {
	RequiredMethods  []string
	satisfiedMethods []string
	id               string
}

func AddToContext(ctx ssh.Context) {
	p := &PartialAuthenticationHelper{
		RequiredMethods: []string{KeyboardInteractiveAuthMethod, PublicKeyAuthMethod},
		id:              ctx.SessionID(),
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

// Returns true if all required methods have been satisfied
func (t *PartialAuthenticationHelper) Satisfied() bool {
	sort.Strings(t.RequiredMethods)
	sort.Strings(t.satisfiedMethods)
	fmt.Printf("%s: satisfied:%v, required: %v\n", t.id, t.satisfiedMethods, t.RequiredMethods)
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
