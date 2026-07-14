package webshell

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// ─── 文件管理 ─────────────────────────────────────────────────────────────────

func (m *Module) filesListDir(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	files, err := m.getAgent(sh).ListDir(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "files": files, "path": req.Path})
}

func (m *Module) filesReadFile(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	content, err := m.getAgent(sh).ReadFile(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "content": string(content)})
}

func (m *Module) filesWriteFile(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if err := m.getAgent(sh).WriteFile(req.Path, []byte(req.Content)); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// filesUpload 上传二进制文件，Content 字段为 base64 编码的文件内容。
func (m *Module) filesUpload(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"` // base64 编码
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content 不是有效 base64"})
		return
	}
	if err := m.getAgent(sh).UploadFile(req.Path, data); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesDeletePath(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败"})
		return
	}
	if err := m.getAgent(sh).DeletePath(req.Path); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesRename(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		OldPath string `json:"oldPath"`
		NewPath string `json:"newPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.OldPath == "" || req.NewPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少路径参数"})
		return
	}
	if err := m.getAgent(sh).RenameFile(req.OldPath, req.NewPath); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesMkDir(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	if err := m.getAgent(sh).MkDir(req.Path); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesDownload(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	data, err := m.getAgent(sh).DownloadFile(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"content": base64.StdEncoding.EncodeToString(data),
		"size":    len(data),
	})
}

func (m *Module) filesHash(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	hash, err := m.getAgent(sh).GetFileHash(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hash": hash})
}

// ─── 文件扩展操作 ─────────────────────────────────────────────────────────────

func (m *Module) filesAppend(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		data = []byte(req.Content)
	}
	if err := m.getAgent(sh).AppendFile(req.Path, data); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesGetTimestamp(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	ts, err := m.getAgent(sh).GetFileTimestamp(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "atime": ts.Atime, "mtime": ts.Mtime, "ctime": ts.Ctime})
}

func (m *Module) filesUpdateTimestamp(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path  string `json:"path"`
		Atime int64  `json:"atime"`
		Mtime int64  `json:"mtime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	if err := m.getAgent(sh).UpdateFileTimestamp(req.Path, req.Atime, req.Mtime); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesCreateFile(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	if err := m.getAgent(sh).CreateFile(req.Path); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (m *Module) filesCheckExist(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct{ Path string `json:"path"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 path 参数"})
		return
	}
	exists, err := m.getAgent(sh).CheckFileExist(req.Path)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "exists": exists})
}

func (m *Module) filesDownloadPart(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path       string `json:"path"`
		BlockIndex int    `json:"blockIndex"`
		BlockSize  int    `json:"blockSize"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	if req.BlockSize <= 0 {
		req.BlockSize = 1048576 // 1 MB
	}
	data, err := m.getAgent(sh).DownloadFilePart(req.Path, req.BlockIndex, req.BlockSize)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"content": base64.StdEncoding.EncodeToString(data),
		"size":    len(data),
	})
}

func (m *Module) filesUploadChunk(w http.ResponseWriter, r *http.Request, id string) {
	sh, ok := m.loadShell(w, id)
	if !ok {
		return
	}
	var req struct {
		Path       string `json:"path"`
		BlockIndex int    `json:"blockIndex"`
		BlockSize  int    `json:"blockSize"`
		Content    string `json:"content"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少参数"})
		return
	}
	if req.BlockSize <= 0 {
		req.BlockSize = 1048576
	}
	data, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content 不是有效 base64"})
		return
	}
	if err := m.getAgent(sh).UpdateFileChunk(req.Path, req.BlockIndex, req.BlockSize, data); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
