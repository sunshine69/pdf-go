package web

import (
	"embed"
	"io/fs"
)

//go:embed spa admin
var files embed.FS

// SPA returns the embedded files of one app, rooted at its directory.
func SPA(name string) fs.FS {
	sub, err := fs.Sub(files, name)
	if err != nil {
		return nil
	}
	return sub
}
