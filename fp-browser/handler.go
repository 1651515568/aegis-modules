package fpbrowser

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"redops/core"
)

func (m *Module) Routes() []core.Route {
	return []core.Route{
		{Method: "GET", Path: "/fingerprints",            Handler: http.HandlerFunc(m.handleFingerprints),          Permission: "fp-browser:view"},
		{Method: "GET", Path: "/fingerprints/categories", Handler: http.HandlerFunc(m.handleFingerprintCategories), Permission: "fp-browser:view"},
		{Method: "GET", Path: "/fingerprints/detail",     Handler: http.HandlerFunc(m.handleFingerprintDetail),     Permission: "fp-browser:view"},
	}
}

func (m *Module) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := strings.ToLower(strings.TrimSpace(q.Get("search")))
	category := q.Get("category")
	hasFav := q.Get("hasFav") == "true"
	weakOnly := q.Get("weak") == "true"
	priority := 0
	if p, err := strconv.Atoi(q.Get("priority")); err == nil && p >= 1 && p <= 3 {
		priority = p
	}
	page, pageSize := 1, 50
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(q.Get("pageSize")); err == nil && ps > 0 && ps <= 200 {
		pageSize = ps
	}
	type FPItem struct {
		Name       string   `json:"name"`
		Category   string   `json:"category"`
		Tags       []string `json:"tags"`
		FavCount   int      `json:"favCount"`
		ProbeCount int      `json:"probeCount"`
		Priority   int      `json:"priority"`
	}
	rules := loadFPRules()
	filtered := make([]FPItem, 0, len(rules))
	for _, rule := range rules {
		if category != "" && rule.Category != category {
			continue
		}
		if priority > 0 && rule.Priority != priority {
			continue
		}
		favCount := 0
		for _, p := range rule.Probes {
			for _, mt := range p.Matchers {
				if mt.Type == "favicon" {
					favCount += len(mt.Favicon)
				}
			}
		}
		if hasFav && favCount == 0 {
			continue
		}
		if weakOnly && (len(rule.Probes) > 1 || favCount > 0) {
			continue
		}
		if search != "" {
			hit := strings.Contains(strings.ToLower(rule.Name), search)
			if !hit {
				for _, t := range rule.Tags {
					if strings.Contains(strings.ToLower(t), search) {
						hit = true
						break
					}
				}
			}
			if !hit {
				continue
			}
		}
		filtered = append(filtered, FPItem{
			Name:       rule.Name,
			Category:   rule.Category,
			Tags:       rule.Tags,
			FavCount:   favCount,
			ProbeCount: len(rule.Probes),
			Priority:   rule.Priority,
		})
	}
	total := len(filtered)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	writeJSON(w, 200, map[string]interface{}{
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
		"items":    filtered[start:end],
	})
}

func (m *Module) handleFingerprintCategories(w http.ResponseWriter, r *http.Request) {
	type CatInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	rules := loadFPRules()
	counts := map[string]int{}
	for _, rule := range rules {
		counts[rule.Category]++
	}
	cats := make([]CatInfo, 0, len(counts))
	for name, cnt := range counts {
		cats = append(cats, CatInfo{Name: name, Count: cnt})
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i].Name < cats[j].Name })
	writeJSON(w, 200, map[string]interface{}{"categories": cats})
}

func (m *Module) handleFingerprintDetail(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, 400, map[string]string{"error": "name 不能为空"})
		return
	}
	for _, rule := range loadFPRules() {
		if rule.Name == name {
			writeJSON(w, 200, rule)
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "未找到"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
