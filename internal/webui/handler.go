package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist
var assets embed.FS

// Handler serves the built console and falls back to index.html for client-side
// routes. API-looking paths are never rewritten, so a misspelled API endpoint
// remains a 404 instead of returning HTML.
func Handler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		clean := path.Clean("/" + r.URL.Path)
		if strings.HasPrefix(clean, "/v1/") || strings.HasPrefix(clean, "/scim/") || clean == "/metrics" || clean == "/healthz" {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(clean, "/")
		if name != "" {
			if info, statErr := fs.Stat(dist, name); statErr == nil && !info.IsDir() {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}
