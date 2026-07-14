package subdomain

import (
	_ "embed"
	"strings"
)

//go:embed wordlists/small.txt
var smallWordlistRaw string

//go:embed wordlists/medium.txt
var mediumWordlistRaw string

//go:embed wordlists/large.txt
var largeWordlistRaw string

//go:embed wordlists/xlarge.txt
var xlargeWordlistRaw string

// getWordlist returns the subdomain prefix list for the given preset.
// preset: "small" | "medium" | "large" | "xlarge"
func getWordlist(preset string) []string {
	raw := mediumWordlistRaw
	switch preset {
	case "small":
		raw = smallWordlistRaw
	case "large":
		raw = largeWordlistRaw
	case "xlarge":
		raw = xlargeWordlistRaw
	}
	var words []string
	for _, line := range strings.Split(raw, "\n") {
		w := strings.TrimSpace(line)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
}
