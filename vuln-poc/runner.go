package vulnpoc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"redops/core"
)

var nucleiBinCandidates = []string{
	"/home/sshuser/.local/bin/nuclei",
	"/usr/local/bin/nuclei",
	"/usr/bin/nuclei",
	"nuclei",
}

func findNuclei() (string, error) {
	for _, p := range nucleiBinCandidates {
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "nuclei")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("nuclei 未找到")
}

// resolveTemplate 将相对路径模板解析为绝对路径（在官方和自定义模板目录中查找）。
func resolveTemplate(tmpl string) string {
	if filepath.IsAbs(tmpl) {
		return tmpl
	}
	home, _ := os.UserHomeDir()
	roots := []string{
		filepath.Join(home, "nuclei-templates"),
		filepath.Join(home, "custom-templates"),
	}
	for _, root := range roots {
		full := filepath.Join(root, tmpl)
		if _, err := os.Stat(full); err == nil {
			return full
		}
		// 也尝试加 .yaml 后缀
		if _, err := os.Stat(full + ".yaml"); err == nil {
			return full + ".yaml"
		}
	}
	return tmpl
}

type nucleiHit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	CurlCmd   string `json:"curl-command"`
	IP        string `json:"ip"`
}

type runner struct {
	log   core.Logger
	store *store
}

func newRunner(log core.Logger, st *store) *runner {
	return &runner{log: log, store: st}
}

// Run 对单条 entry 执行 nuclei PoC 验证。
func (r *runner) Run(ctx context.Context, entryID string) {
	entry := r.store.get(entryID)
	if entry == nil {
		return
	}

	result := RunResult{RunAt: time.Now()}

	bin, err := findNuclei()
	if err != nil {
		result.ErrMsg = err.Error()
		r.finalize(entryID, result)
		return
	}

	tmplPath := resolveTemplate(entry.Template)

	// 目标临时文件
	tmpTarget, err := os.CreateTemp("", "poc-target-*.txt")
	if err != nil {
		result.ErrMsg = "创建临时文件失败: " + err.Error()
		r.finalize(entryID, result)
		return
	}
	_, _ = fmt.Fprintln(tmpTarget, entry.Target)
	tmpTarget.Close()
	defer os.Remove(tmpTarget.Name())

	args := []string{
		"-list", tmpTarget.Name(),
		"-t", tmplPath,
		"-jsonl",
		"-silent",
		"-no-color",
		"-timeout", "15",
		"-retries", "1",
		"-rate-limit", "50",
	}

	r.log.Info("poc run", "entry", entryID, "target", entry.Target, "template", tmplPath)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.ErrMsg = "pipe: " + err.Error()
		r.finalize(entryID, result)
		return
	}
	if err := cmd.Start(); err != nil {
		result.ErrMsg = "start: " + err.Error()
		r.finalize(entryID, result)
		return
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var hits []nucleiHit
	for sc.Scan() {
		var h nucleiHit
		if json.Unmarshal(sc.Bytes(), &h) == nil {
			hits = append(hits, h)
		}
	}
	_ = cmd.Wait()

	if ctx.Err() != nil {
		result.ErrMsg = "已取消"
		r.finalize(entryID, result)
		return
	}

	if len(hits) > 0 {
		h := hits[0]
		result.Found = true
		result.CurlCmd = h.CurlCmd
		result.Request = truncate(h.Request, 4096)
		result.Response = truncate(h.Response, 4096)
		result.Output = fmt.Sprintf("[%s] %s => %s", h.Info.Severity, h.Info.Name, h.MatchedAt)
		r.log.Info("poc hit", "entry", entryID, "template", h.TemplateID, "matched", h.MatchedAt)
	} else {
		r.log.Info("poc miss", "entry", entryID)
	}

	r.finalize(entryID, result)
}

func (r *runner) finalize(entryID string, result RunResult) {
	r.store.endRun(entryID)
	r.store.update(entryID, func(e *Entry) {
		// 保留最近10次运行记录
		e.Runs = append(e.Runs, result)
		if len(e.Runs) > 10 {
			e.Runs = e.Runs[len(e.Runs)-10:]
		}
		// 根据结果自动推进状态
		if result.Found && e.Status == StatusUnconfirmed {
			e.Status = StatusConfirmed
		}
	})
	r.store.save()
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "…[截断]"
	}
	return s
}

// TemplateSearch 在模板目录中按关键词搜索模板文件名（用于前端自动补全）。
func TemplateSearch(keyword string, limit int) []string {
	if keyword == "" || limit <= 0 {
		return nil
	}
	home, _ := os.UserHomeDir()
	roots := []string{
		filepath.Join(home, "nuclei-templates"),
		filepath.Join(home, "custom-templates"),
	}
	kw := strings.ToLower(keyword)
	var results []string
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".yaml") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Contains(strings.ToLower(rel), kw) {
				results = append(results, rel)
				if len(results) >= limit {
					return filepath.SkipAll
				}
			}
			return nil
		})
		if len(results) >= limit {
			break
		}
	}
	return results
}
