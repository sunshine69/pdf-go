//go:build unix

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// promptHidden reads a line with echo off. When stdin is not a terminal the
// line is read normally, so `... | signsrv-utils admin add x@y.z` still works
// and does not silently swallow input behind an invisible prompt.
func promptHidden(label string) (string, error) {
	fd := int(os.Stdin.Fd())
	g, tty := noEcho(fd)
	defer g.Restore()

	if tty {
		// Echo is off, so the prompt has to go to stderr and the operator gets
		// no feedback as they type. That is the trade, and it is the correct one.
		fmt.Fprint(os.Stderr, label)
		defer fmt.Fprint(os.Stderr, "\n")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if err == io.EOF && line == "" {
		return "", fmt.Errorf("no input on stdin (set ADMIN_PASSWORD or run this on a terminal)")
	}
	return trimLine(line), nil
}

type echoGuard struct {
	fd     int
	saved  syscall.Termios
	active bool
}

func noEcho(fd int) (*echoGuard, bool) {
	var t syscall.Termios
	if err := ioctlTerm(fd, syscall.TCGETS, &t); err != nil {
		return nil, false
	}
	g := &echoGuard{fd: fd, saved: t, active: true}
	t.Lflag &^= uint32(syscall.ECHO | syscall.ECHONL | syscall.ECHOCTL)
	if err := ioctlTerm(fd, syscall.TCSETS, &t); err != nil {
		return nil, false
	}
	return g, true
}

func (g *echoGuard) Restore() {
	if g == nil || !g.active {
		return
	}
	saved := g.saved
	_ = ioctlTerm(g.fd, syscall.TCSETS, &saved)
	g.active = false
}

func ioctlTerm(fd int, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req,
		uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}
