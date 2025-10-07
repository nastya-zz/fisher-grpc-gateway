package paths

import "strings"

var publicPaths = []string{
	"/v1/auth/login",
	"/v1/auth/register",
	"/v1/auth/access",
	"/v1/auth/refresh",
}

// publicPaths returns list of public path patterns from env PUBLIC_PATHS.
// Comma-separated, supports exact match ("/healthz") and prefix match with '*' ("/auth/*").
func PublicPaths() []string {
	parts := publicPaths
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func IsPublicPath(path string, patterns []string) bool {
	for _, pat := range patterns {
		if strings.HasSuffix(pat, "*") {
			prefix := strings.TrimSuffix(pat, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == pat {
			return true
		}
	}
	return false
}