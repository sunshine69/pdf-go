package web

import (
	"embed"
	"io/fs"
)

//go:embed spa admin templates
var files embed.FS

// Templates returns the embedded email templates, rooted at web/templates.
// They are inside the binary, so the service can send mail with no file
// installed on disk.
func Templates() fs.FS {
	sub, err := fs.Sub(files, "templates")
	if err != nil {
		return nil
	}
	return sub
}

// SPA returns the embedded files of one app, rooted at its directory.
func SPA(name string) fs.FS {
	sub, err := fs.Sub(files, name)
	if err != nil {
		return nil
	}
	return sub
}
