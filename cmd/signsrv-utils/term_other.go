//go:build !unix

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// promptHidden is the portable fallback: without terminal ioctls there is no
// way to turn echo off, so the password would be visible as it is typed.
// Rather than pretend otherwise, this build refuses an interactive read and
// tells the operator to use the environment variable instead.
func promptHidden(label string) (string, error) {
	if fi, err := os.Stdin.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("cannot disable echo on this platform; set SIGNSRV_ADMIN_PASSWORD instead")
	}
	fmt.Fprint(os.Stderr, label)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if err == io.EOF && line == "" {
		return "", fmt.Errorf("no input on stdin (set SIGNSRV_ADMIN_PASSWORD)")
	}
	return trimLine(line), nil
}

var _ = strings.TrimSpace
