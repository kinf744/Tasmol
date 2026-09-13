// Package web embeds the Web UI assets (templates + static) into the Go
// binary so the management interface is served without any files on disk.
// This is required inside the Android APK and keeps Termux installs working
// without copying the web/ directory next to the binary.
package web

import "embed"

// FS holds templates/index.html and static/app.js.
//
//go:embed templates static
var FS embed.FS
