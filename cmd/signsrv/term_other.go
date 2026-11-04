//go:build !unix

package main

// Password reading on non-Unix systems falls back to plain stdin: there is no
// terminal control to do, and the service is deployed on Linux.
type echoGuard struct{}

func noEcho(fd int) (*echoGuard, bool) { return nil, false }
func (g *echoGuard) Restore()          {}
func isTerminal() bool                 { return false }
