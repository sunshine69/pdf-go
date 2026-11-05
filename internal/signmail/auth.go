package signmail

import (
	"errors"
	"net/smtp"
)

// LOGIN is the authentication mechanism most mail relays advertise, and the
// one the service is configured with. net/smtp has no LOGIN implementation,
// so this is the whole of it: two base64 lines, the user and the password.
//
// The server's challenges are "Username:" and "Password:". The initial
// response of the AUTH command is the username, which is the accepted shape:
// a server that sends the username challenge first discards the first
// challenge once it has data, and a server that expects the username in the
// first line takes it.
type loginAuth struct {
	username, password string
}

// LoginAuth returns an smtp.Auth for the LOGIN mechanism.
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	if a.username == "" {
		return "", nil, errors.New("signmail: login auth has no username")
	}
	return "LOGIN", []byte(a.username), nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		// The server sent the password challenge.
		return []byte(a.password), nil
	}
	return nil, nil
}
