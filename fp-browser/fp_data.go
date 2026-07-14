package fpbrowser

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed fingerprints.json
var fingerprintsData []byte

type fpRule struct {
	Name     string    `json:"name"`
	Category string    `json:"category"`
	Tags     []string  `json:"tags"`
	Priority int       `json:"priority"`
	Probes   []fpProbe `json:"probes"`
}

type fpProbe struct {
	Path     string            `json:"path"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"request_headers,omitempty"`
	Matchers []fpMatcher       `json:"matchers"`
}

type fpMatcher struct {
	Type     string   `json:"type"`
	Keywords []string `json:"keywords"`
	Status   int      `json:"status"`
	Favicon  []string `json:"favicon"`
}

var (
	fpRules     []fpRule
	fpRulesOnce sync.Once
)

func loadFPRules() []fpRule {
	fpRulesOnce.Do(func() {
		if err := json.Unmarshal(fingerprintsData, &fpRules); err != nil {
			fpRules = nil
		}
	})
	return fpRules
}
