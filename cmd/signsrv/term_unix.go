//go:build unix

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// echoGuard turns off keyboard echo for the duration of a password read and
// restores the previous terminal settings afterwards. It uses the terminal
// ioctls through syscall, so the service keeps the project rule of no cgo and
// no extra module: the only thing this needs is the kernel.
//
// ICANON stays on so the line stays buffered and Enter submits it; only ECHO
// is cleared, which is what a password prompt needs.
type echoGuard struct {
	fd     int
	saved  syscall.Termios
	active bool
}

// noEcho disables echo on fd. It reports false when fd is not a terminal, in
// which case the caller reads from a pipe and there is nothing to silence.
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

// Restore puts the terminal settings back. Safe to call on a nil guard, which
// is what happens when the read was not a terminal.
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

// isTerminal reports whether stdin is an interactive terminal.
func isTerminal() bool {
	g, ok := noEcho(int(os.Stdin.Fd()))
	g.Restore()
	return ok
}
