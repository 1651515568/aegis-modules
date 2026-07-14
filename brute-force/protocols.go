package bruteforce

import (
	"bufio"
	"bytes"
	"context"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec
	"crypto/rand"
	"crypto/sha1" //nolint:gosec
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

// ProbeResult holds the outcome of a single credential probe.
type ProbeResult struct {
	Success  bool
	AuthFail bool // true = wrong creds (vs. connection error)
	Err      error
}

// Prober is the interface implemented by all protocol probers.
type Prober interface {
	Name() string
	DefaultPort() int
	Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult
}

// isAuthError returns true when the error represents an authentication failure
// (wrong credentials) rather than a network/connection error.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, kw := range []string{
		"authentication failed", "auth failed", "permission denied",
		"access denied", "login incorrect", "invalid password",
		"bad password", "incorrect password", "wrong password",
		"535", "530", "login failed", "authentication error",
		"invalid username", "user auth failure",
	} {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// dialWithTimeout opens a TCP connection with timeout derived from timeoutMs.
func dialWithTimeout(ctx context.Context, host string, port, timeoutMs int) (net.Conn, error) {
	d := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
	addr := fmt.Sprintf("%s:%d", host, port)
	return d.DialContext(ctx, "tcp", addr)
}

// ─── SSH ─────────────────────────────────────────────────────────────────────

// SSHProber tests SSH credentials using golang.org/x/crypto/ssh.
type SSHProber struct{}

func (p *SSHProber) Name() string       { return "ssh" }
func (p *SSHProber) DefaultPort() int   { return 22 }

func (p *SSHProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         time.Duration(timeoutMs) * time.Millisecond,
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	// Use a channel to support context cancellation
	type dialResult struct {
		conn *ssh.Client
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, err := ssh.Dial("tcp", addr, cfg)
		ch <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return ProbeResult{Err: ctx.Err()}
	case res := <-ch:
		if res.err != nil {
			return ProbeResult{Err: res.err, AuthFail: isAuthError(res.err)}
		}
		res.conn.Close()
		return ProbeResult{Success: true}
	}
}

// ─── FTP ─────────────────────────────────────────────────────────────────────

// FTPProber tests FTP credentials using raw TCP (RFC 959).
type FTPProber struct{}

func (p *FTPProber) Name() string     { return "ftp" }
func (p *FTPProber) DefaultPort() int { return 21 }

func (p *FTPProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	reader := bufio.NewReader(conn)

	// Read banner (220 ...)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220") {
		return ProbeResult{Err: fmt.Errorf("ftp: unexpected banner: %s", strings.TrimSpace(line))}
	}
	// Some servers send multi-line banners (220-)
	for strings.HasPrefix(line, "220-") {
		line, err = reader.ReadString('\n')
		if err != nil {
			return ProbeResult{Err: fmt.Errorf("ftp: reading banner: %w", err)}
		}
	}

	// Send USER
	if _, err = fmt.Fprintf(conn, "USER %s\r\n", username); err != nil {
		return ProbeResult{Err: err}
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: err}
	}
	// 331 = password required, 230 = logged in without password
	if strings.HasPrefix(line, "230") {
		return ProbeResult{Success: true}
	}
	if !strings.HasPrefix(line, "331") {
		return ProbeResult{Err: fmt.Errorf("ftp: unexpected user response: %s", strings.TrimSpace(line)), AuthFail: strings.HasPrefix(line, "530") || strings.HasPrefix(line, "332")}
	}

	// Send PASS
	if _, err = fmt.Fprintf(conn, "PASS %s\r\n", password); err != nil {
		return ProbeResult{Err: err}
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: err}
	}
	if strings.HasPrefix(line, "230") {
		return ProbeResult{Success: true}
	}
	return ProbeResult{Err: fmt.Errorf("ftp: %s", strings.TrimSpace(line)), AuthFail: true}
}

// ─── HTTP Basic ───────────────────────────────────────────────────────────────

// HTTPBasicProber tests HTTP Basic Authentication credentials.
type HTTPBasicProber struct{}

func (p *HTTPBasicProber) Name() string     { return "http-basic" }
func (p *HTTPBasicProber) DefaultPort() int { return 80 }

func (p *HTTPBasicProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	target := fmt.Sprintf("%s://%s:%d/", scheme, host, port)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AEGIS/1.0)")

	client := makeHTTPProbeClient(timeoutMs)
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return ProbeResult{Err: fmt.Errorf("http-basic: %d", resp.StatusCode), AuthFail: true}
	}
	if resp.StatusCode < 400 {
		return ProbeResult{Success: true}
	}
	return ProbeResult{Err: fmt.Errorf("http-basic: status %d", resp.StatusCode), AuthFail: false}
}

// ─── HTTP Form ────────────────────────────────────────────────────────────────

// HTTPFormOptions configures the HTTP form login prober.
type HTTPFormOptions struct {
	URL         string
	UserField   string
	PassField   string
	SuccessCode int
	FailText    string
}

// HTTPFormProber tests credentials against an HTML login form via POST.
type HTTPFormProber struct {
	Opts HTTPFormOptions
}

func (p *HTTPFormProber) Name() string     { return "http-form" }
func (p *HTTPFormProber) DefaultPort() int { return 80 }

func (p *HTTPFormProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	formURL := p.Opts.URL
	if formURL == "" {
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		formURL = fmt.Sprintf("%s://%s:%d/login", scheme, host, port)
	}
	userField := p.Opts.UserField
	if userField == "" {
		userField = "username"
	}
	passField := p.Opts.PassField
	if passField == "" {
		passField = "password"
	}
	successCode := p.Opts.SuccessCode
	if successCode == 0 {
		successCode = 200
	}

	formData := url.Values{}
	formData.Set(userField, username)
	formData.Set(passField, password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, formURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AEGIS/1.0)")

	client := makeHTTPProbeClient(timeoutMs)
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	if p.Opts.FailText != "" && bytes.Contains(body, []byte(p.Opts.FailText)) {
		return ProbeResult{Err: fmt.Errorf("http-form: fail text found in response"), AuthFail: true}
	}
	if resp.StatusCode == successCode {
		return ProbeResult{Success: true}
	}
	return ProbeResult{Err: fmt.Errorf("http-form: status %d", resp.StatusCode), AuthFail: true}
}

// makeHTTPProbeClient creates a short-lived HTTP client for probe requests.
func makeHTTPProbeClient(timeoutMs int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// ─── MySQL ────────────────────────────────────────────────────────────────────

// MySQLProber tests MySQL credentials using the mysql_native_password protocol.
type MySQLProber struct{}

func (p *MySQLProber) Name() string     { return "mysql" }
func (p *MySQLProber) DefaultPort() int { return 3306 }

func (p *MySQLProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Read initial handshake packet
	pktLen, _, err := readMySQLPacket(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mysql: read handshake: %w", err)}
	}
	if pktLen < 1 {
		return ProbeResult{Err: fmt.Errorf("mysql: empty handshake")}
	}

	// Read handshake payload
	payload := make([]byte, pktLen)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return ProbeResult{Err: fmt.Errorf("mysql: read handshake payload: %w", err)}
	}

	// Parse protocol version
	if len(payload) < 1 {
		return ProbeResult{Err: fmt.Errorf("mysql: handshake too short")}
	}
	if payload[0] == 0xFF {
		// Error packet
		return ProbeResult{Err: fmt.Errorf("mysql: error packet in handshake")}
	}
	if payload[0] != 10 {
		return ProbeResult{Err: fmt.Errorf("mysql: unsupported protocol version %d", payload[0])}
	}

	// Skip server version (null-terminated string)
	pos := 1
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	pos++ // skip null terminator

	// Skip connection id (4 bytes)
	pos += 4

	if pos+8 > len(payload) {
		return ProbeResult{Err: fmt.Errorf("mysql: handshake truncated at challenge")}
	}

	// Auth plugin data part 1 (8 bytes)
	challenge := make([]byte, 0, 20)
	challenge = append(challenge, payload[pos:pos+8]...)
	pos += 8
	pos++ // skip filler byte (0x00)

	// Capabilities (2 bytes)
	if pos+2 > len(payload) {
		return ProbeResult{Err: fmt.Errorf("mysql: handshake truncated at capabilities")}
	}
	capLow := uint16(payload[pos]) | uint16(payload[pos+1])<<8
	pos += 2
	_ = capLow

	// Character set, status flags, capabilities high, auth data length
	if pos+11 > len(payload) {
		return ProbeResult{Err: fmt.Errorf("mysql: handshake truncated")}
	}
	// auth_plugin_data_len is at pos+2
	authDataLen := int(payload[pos+2])
	pos += 11 // skip charset(1) + status(2) + cap_high(2) + auth_data_len(1) + reserved(10)

	// Auth plugin data part 2
	part2Len := authDataLen - 8
	if part2Len < 12 {
		part2Len = 12
	}
	if pos+part2Len > len(payload) {
		part2Len = len(payload) - pos
	}
	if part2Len > 0 {
		challenge = append(challenge, payload[pos:pos+part2Len]...)
		pos += part2Len
		// Remove trailing null byte from challenge
		if len(challenge) > 0 && challenge[len(challenge)-1] == 0 {
			challenge = challenge[:len(challenge)-1]
		}
	}
	// Ensure challenge is exactly 20 bytes (trim if longer)
	if len(challenge) > 20 {
		challenge = challenge[:20]
	}

	// Compute mysql_native_password: SHA1(password) XOR SHA1(challenge || SHA1(SHA1(password)))
	authResp := mysqlNativePassword([]byte(password), challenge)

	// Build client handshake response (protocol 41)
	// Capabilities: CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD
	capFlags := uint32(0x00000001 | // CLIENT_LONG_PASSWORD
		0x00000200 | // CLIENT_PROTOCOL_41
		0x00008000 | // CLIENT_SECURE_CONNECTION
		0x00000200) // CLIENT_PROTOCOL_41

	var buf bytes.Buffer
	// Capability flags (4 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, capFlags)
	// Max packet size (4 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1<<24-1))
	// Character set (1 byte): utf8mb4
	buf.WriteByte(0x21)
	// Reserved (23 bytes)
	buf.Write(make([]byte, 23))
	// Username (null-terminated)
	buf.WriteString(username)
	buf.WriteByte(0)
	// Auth response (length-prefixed)
	buf.WriteByte(byte(len(authResp)))
	buf.Write(authResp)
	// Database (null-terminated, empty = none)
	buf.WriteByte(0)

	// Send packet (sequence 1)
	pktData := buf.Bytes()
	header := make([]byte, 4)
	header[0] = byte(len(pktData))
	header[1] = byte(len(pktData) >> 8)
	header[2] = byte(len(pktData) >> 16)
	header[3] = 1 // sequence number
	if _, err = conn.Write(append(header, pktData...)); err != nil {
		return ProbeResult{Err: fmt.Errorf("mysql: send auth: %w", err)}
	}

	// Read server response
	respLen, _, err := readMySQLPacket(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mysql: read auth response: %w", err)}
	}
	if respLen < 1 {
		return ProbeResult{Err: fmt.Errorf("mysql: empty auth response")}
	}
	respPayload := make([]byte, respLen)
	if _, err = io.ReadFull(conn, respPayload); err != nil {
		return ProbeResult{Err: fmt.Errorf("mysql: read auth response payload: %w", err)}
	}

	switch respPayload[0] {
	case 0x00: // OK
		return ProbeResult{Success: true}
	case 0xFF: // ERR
		authFail := true
		var errMsg string
		if len(respPayload) > 9 {
			errMsg = string(respPayload[9:])
		}
		return ProbeResult{Err: fmt.Errorf("mysql: auth failed: %s", errMsg), AuthFail: authFail}
	case 0xFE: // EOF / auth switch request
		return ProbeResult{Err: fmt.Errorf("mysql: auth switch requested (unsupported)"), AuthFail: false}
	default:
		return ProbeResult{Err: fmt.Errorf("mysql: unexpected response byte 0x%02x", respPayload[0])}
	}
}

// readMySQLPacket reads a 4-byte MySQL packet header and returns (length, seqNum, error).
func readMySQLPacket(r io.Reader) (int, byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, err
	}
	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seqNum := hdr[3]
	return pktLen, seqNum, nil
}

// mysqlNativePassword computes the MySQL native password hash:
// SHA1(password) XOR SHA1(challenge || SHA1(SHA1(password)))
func mysqlNativePassword(password, challenge []byte) []byte {
	if len(password) == 0 {
		return nil
	}
	h := sha1.New() //nolint:gosec
	h.Write(password)
	sha1Pass := h.Sum(nil) // SHA1(password)

	h.Reset()
	h.Write(sha1Pass)
	sha1sha1Pass := h.Sum(nil) // SHA1(SHA1(password))

	h.Reset()
	h.Write(challenge)
	h.Write(sha1sha1Pass)
	hashResult := h.Sum(nil) // SHA1(challenge || SHA1(SHA1(password)))

	// XOR sha1Pass with hashResult
	result := make([]byte, sha1.Size)
	for i := range result {
		result[i] = sha1Pass[i] ^ hashResult[i]
	}
	return result
}

// ─── Redis ────────────────────────────────────────────────────────────────────

// RedisProber tests Redis credentials using the RESP protocol.
type RedisProber struct{}

func (p *RedisProber) Name() string     { return "redis" }
func (p *RedisProber) DefaultPort() int { return 6379 }

func (p *RedisProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	reader := bufio.NewReader(conn)

	var cmd string
	if username != "" && username != "default" {
		// Redis 6.0+ ACL: AUTH username password
		cmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(username), username, len(password), password)
	} else if password != "" {
		// Redis < 6.0: AUTH password
		cmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(password), password)
	} else {
		// No password: send PING
		cmd = "*1\r\n$4\r\nPING\r\n"
	}

	if _, err = conn.Write([]byte(cmd)); err != nil {
		return ProbeResult{Err: err}
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: err}
	}
	line = strings.TrimSpace(line)

	if line == "+OK" || line == "+PONG" {
		return ProbeResult{Success: true}
	}
	if strings.HasPrefix(line, "-") {
		msg := strings.TrimPrefix(line, "-")
		return ProbeResult{Err: fmt.Errorf("redis: %s", msg), AuthFail: true}
	}
	return ProbeResult{Err: fmt.Errorf("redis: unexpected response: %s", line)}
}

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

// PostgreSQLProber tests PostgreSQL credentials using the wire protocol.
type PostgreSQLProber struct{}

func (p *PostgreSQLProber) Name() string     { return "postgresql" }
func (p *PostgreSQLProber) DefaultPort() int { return 5432 }

func (p *PostgreSQLProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Build startup message
	var startupBuf bytes.Buffer
	// Protocol version 3.0 = 196608
	_ = binary.Write(&startupBuf, binary.BigEndian, uint32(196608))
	startupBuf.WriteString("user\x00")
	startupBuf.WriteString(username)
	startupBuf.WriteByte(0)
	startupBuf.WriteString("database\x00")
	startupBuf.WriteString("postgres")
	startupBuf.WriteByte(0)
	startupBuf.WriteByte(0) // terminator

	// Length prefix (includes itself)
	msgLen := uint32(4 + startupBuf.Len())
	var msg bytes.Buffer
	_ = binary.Write(&msg, binary.BigEndian, msgLen)
	msg.Write(startupBuf.Bytes())

	if _, err = conn.Write(msg.Bytes()); err != nil {
		return ProbeResult{Err: fmt.Errorf("postgresql: send startup: %w", err)}
	}

	// Read response
	msgType, payload, err := readPGMessage(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("postgresql: read startup response: %w", err)}
	}

	switch msgType {
	case 'R': // Authentication request
		if len(payload) < 4 {
			return ProbeResult{Err: fmt.Errorf("postgresql: auth request too short")}
		}
		authType := binary.BigEndian.Uint32(payload[:4])
		switch authType {
		case 0: // AuthOK — server accepted without password
			return ProbeResult{Success: true}
		case 3: // CleartextPassword
			return pgSendClearPassword(conn, password)
		case 5: // MD5Password
			if len(payload) < 8 {
				return ProbeResult{Err: fmt.Errorf("postgresql: md5 auth: payload too short")}
			}
			salt := payload[4:8]
			return pgSendMD5Password(conn, username, password, salt)
		default:
			return ProbeResult{Err: fmt.Errorf("postgresql: unsupported auth type %d", authType)}
		}
	case 'E': // Error
		msg := pgParseError(payload)
		return ProbeResult{Err: fmt.Errorf("postgresql: %s", msg), AuthFail: true}
	default:
		return ProbeResult{Err: fmt.Errorf("postgresql: unexpected message type '%c'", msgType)}
	}
}

func pgSendClearPassword(conn net.Conn, password string) ProbeResult {
	// PasswordMessage: 'p' + length(4) + password + '\0'
	msgLen := uint32(4 + len(password) + 1)
	var buf bytes.Buffer
	buf.WriteByte('p')
	_ = binary.Write(&buf, binary.BigEndian, msgLen)
	buf.WriteString(password)
	buf.WriteByte(0)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return ProbeResult{Err: fmt.Errorf("postgresql: send cleartext password: %w", err)}
	}
	return pgReadAuthResult(conn)
}

func pgSendMD5Password(conn net.Conn, username, password string, salt []byte) ProbeResult {
	// md5(md5(password + username) + salt_as_bytes_not_hex)
	h := md5.New() //nolint:gosec
	h.Write([]byte(password))
	h.Write([]byte(username))
	inner := fmt.Sprintf("%x", h.Sum(nil))

	h.Reset()
	h.Write([]byte(inner))
	h.Write(salt)
	hashed := "md5" + fmt.Sprintf("%x", h.Sum(nil))

	// PasswordMessage: 'p' + length(4) + hashed_password + '\0'
	msgLen := uint32(4 + len(hashed) + 1)
	var buf bytes.Buffer
	buf.WriteByte('p')
	_ = binary.Write(&buf, binary.BigEndian, msgLen)
	buf.WriteString(hashed)
	buf.WriteByte(0)
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return ProbeResult{Err: fmt.Errorf("postgresql: send md5 password: %w", err)}
	}
	return pgReadAuthResult(conn)
}

func pgReadAuthResult(conn net.Conn) ProbeResult {
	msgType, payload, err := readPGMessage(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("postgresql: read auth result: %w", err)}
	}
	switch msgType {
	case 'R':
		if len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == 0 {
			return ProbeResult{Success: true}
		}
		return ProbeResult{Err: fmt.Errorf("postgresql: unexpected auth response"), AuthFail: false}
	case 'E':
		msg := pgParseError(payload)
		return ProbeResult{Err: fmt.Errorf("postgresql: %s", msg), AuthFail: true}
	default:
		return ProbeResult{Err: fmt.Errorf("postgresql: unexpected message '%c'", msgType)}
	}
}

// readPGMessage reads one PostgreSQL frontend/backend protocol message.
// Format: 1 byte type + 4 byte length (includes itself) + payload.
func readPGMessage(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:5]))
	if msgLen < 4 {
		return msgType, nil, nil
	}
	payload := make([]byte, msgLen-4)
	if len(payload) > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// pgParseError extracts a human-readable message from a PostgreSQL error payload.
func pgParseError(payload []byte) string {
	// Fields are: type byte + null-terminated string, repeated, terminated by '\0'
	i := 0
	for i < len(payload) {
		fieldType := payload[i]
		i++
		if fieldType == 0 {
			break
		}
		end := bytes.IndexByte(payload[i:], 0)
		if end < 0 {
			break
		}
		val := string(payload[i : i+end])
		i += end + 1
		if fieldType == 'M' { // Message
			return val
		}
	}
	return "authentication failed"
}

// ─── Telnet ───────────────────────────────────────────────────────────────────

// TelnetProber tests Telnet credentials by interacting with the login prompt.
type TelnetProber struct{}

func (p *TelnetProber) Name() string     { return "telnet" }
func (p *TelnetProber) DefaultPort() int { return 23 }

const (
	telnetIAC  = 0xFF
	telnetDO   = 0xFD
	telnetDONT = 0xFE
	telnetWILL = 0xFB
	telnetWONT = 0xFC
	telnetSB   = 0xFA
	telnetSE   = 0xF0
)

func (p *TelnetProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()

	timeout := time.Duration(timeoutMs) * time.Millisecond

	// readUntil reads from conn, negotiating Telnet IAC sequences, until
	// one of the triggers is found in the accumulated text or timeout.
	readUntil := func(triggers []string, perReadTimeout time.Duration) (string, error) {
		var acc strings.Builder
		buf := make([]byte, 1)
		var iacs []byte

		for {
			_ = conn.SetReadDeadline(time.Now().Add(perReadTimeout))
			n, err := conn.Read(buf)
			if n == 0 {
				if err != nil {
					return acc.String(), err
				}
				continue
			}
			b := buf[0]

			// Handle Telnet IAC negotiation
			if b == telnetIAC {
				iacs = append(iacs, b)
				continue
			}
			if len(iacs) == 1 {
				// Command byte after IAC
				iacs = append(iacs, b)
				if b == telnetSB {
					continue // start of sub-negotiation, read until SE
				}
				if b == telnetSE {
					iacs = nil
					continue
				}
				if len(iacs) < 2 {
					continue
				}
				continue
			}
			if len(iacs) == 2 {
				// Option byte
				cmd := iacs[1]
				iacs = nil
				// Respond to negotiations: WILL → WONT, DO → DONT
				var resp []byte
				switch cmd {
				case telnetWILL:
					resp = []byte{telnetIAC, telnetDONT, b}
				case telnetDO:
					resp = []byte{telnetIAC, telnetWONT, b}
				}
				if resp != nil {
					_, _ = conn.Write(resp)
				}
				continue
			}
			iacs = nil

			acc.WriteByte(b)
			text := acc.String()
			textLower := strings.ToLower(text)
			for _, t := range triggers {
				if strings.Contains(textLower, strings.ToLower(t)) {
					return text, nil
				}
			}
		}
	}

	perRead := timeout / 3
	if perRead < 2*time.Second {
		perRead = 2 * time.Second
	}

	// Wait for login prompt
	_, err = readUntil([]string{"login:", "username:", "user name:", "login name:"}, perRead)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("telnet: waiting for login prompt: %w", err)}
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(conn, "%s\n", username); err != nil {
		return ProbeResult{Err: fmt.Errorf("telnet: send username: %w", err)}
	}

	// Wait for password prompt
	_, err = readUntil([]string{"password:", "assword:"}, perRead)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("telnet: waiting for password prompt: %w", err)}
	}

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = fmt.Fprintf(conn, "%s\n", password); err != nil {
		return ProbeResult{Err: fmt.Errorf("telnet: send password: %w", err)}
	}

	// Wait for success or failure indicators
	result, _ := readUntil([]string{
		"$", "#", "last login", ">", "welcome", "% ",
		"incorrect", "denied", "failed", "invalid", "authentication failure",
	}, perRead)

	resultLower := strings.ToLower(result)
	for _, fail := range []string{"incorrect", "denied", "failed", "invalid", "authentication failure"} {
		if strings.Contains(resultLower, fail) {
			return ProbeResult{Err: fmt.Errorf("telnet: authentication failed"), AuthFail: true}
		}
	}
	for _, ok := range []string{"$", "#", "last login", ">", "welcome", "% "} {
		if strings.Contains(result, ok) {
			return ProbeResult{Success: true}
		}
	}

	return ProbeResult{Err: fmt.Errorf("telnet: no definitive result"), AuthFail: false}
}

// ─── SMTP ─────────────────────────────────────────────────────────────────────

// SMTPProber tests SMTP AUTH LOGIN/PLAIN credentials.
type SMTPProber struct{}

func (p *SMTPProber) Name() string     { return "smtp" }
func (p *SMTPProber) DefaultPort() int { return 25 }

func (p *SMTPProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	reader := bufio.NewReader(conn)

	// Read banner
	if err := smtpReadResponse(reader, "220"); err != nil {
		return ProbeResult{Err: fmt.Errorf("smtp: banner: %w", err)}
	}

	// Send EHLO
	if _, err = fmt.Fprintf(conn, "EHLO brutetest\r\n"); err != nil {
		return ProbeResult{Err: fmt.Errorf("smtp: EHLO: %w", err)}
	}
	caps, err := smtpReadMultiResponse(reader, "250")
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smtp: EHLO response: %w", err)}
	}

	capsLower := strings.ToLower(caps)
	supportsLogin := strings.Contains(capsLower, "auth login") || strings.Contains(capsLower, "auth=login")
	supportsPlain := strings.Contains(capsLower, "auth plain") || strings.Contains(capsLower, "auth=plain")

	if supportsPlain {
		// Try AUTH PLAIN: base64("\0username\0password")
		plainStr := "\x00" + username + "\x00" + password
		encoded := base64.StdEncoding.EncodeToString([]byte(plainStr))
		if _, err = fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", encoded); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH PLAIN send: %w", err)}
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH PLAIN response: %w", err)}
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "235") {
			return ProbeResult{Success: true}
		}
		if strings.HasPrefix(line, "535") || strings.HasPrefix(line, "534") {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH PLAIN failed: %s", line), AuthFail: true}
		}
	}

	if supportsLogin {
		// Try AUTH LOGIN
		if _, err = fmt.Fprintf(conn, "AUTH LOGIN\r\n"); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH LOGIN: %w", err)}
		}
		if err = smtpReadResponse(reader, "334"); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH LOGIN 334: %w", err)}
		}

		// Send username in base64
		if _, err = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(username))); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: send username: %w", err)}
		}
		if err = smtpReadResponse(reader, "334"); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: username 334: %w", err)}
		}

		// Send password in base64
		if _, err = fmt.Fprintf(conn, "%s\r\n", base64.StdEncoding.EncodeToString([]byte(password))); err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: send password: %w", err)}
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			return ProbeResult{Err: fmt.Errorf("smtp: AUTH LOGIN response: %w", err)}
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "235") {
			return ProbeResult{Success: true}
		}
		return ProbeResult{Err: fmt.Errorf("smtp: AUTH LOGIN failed: %s", line), AuthFail: true}
	}

	return ProbeResult{Err: fmt.Errorf("smtp: no supported AUTH methods (caps: %s)", caps), AuthFail: false}
}

func smtpReadResponse(r *bufio.Reader, expectedCode string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if len(line) < 4 {
			continue
		}
		code := line[:3]
		if code != expectedCode {
			return fmt.Errorf("expected %s, got: %s", expectedCode, line)
		}
		if line[3] != '-' { // multiline continuation
			return nil
		}
	}
}

func smtpReadMultiResponse(r *bufio.Reader, expectedCode string) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		line = strings.TrimSpace(line)
		sb.WriteString(line)
		sb.WriteString("\n")
		if len(line) < 4 {
			continue
		}
		code := line[:3]
		if code != expectedCode {
			return sb.String(), fmt.Errorf("expected %s, got: %s", expectedCode, line)
		}
		if line[3] != '-' { // not a continuation
			return sb.String(), nil
		}
	}
}

// ─── POP3 ─────────────────────────────────────────────────────────────────────

// POP3Prober tests POP3 credentials (RFC 1939).
type POP3Prober struct{}

func (p *POP3Prober) Name() string     { return "pop3" }
func (p *POP3Prober) DefaultPort() int { return 110 }

func (p *POP3Prober) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	reader := bufio.NewReader(conn)

	// Read banner (+OK ...)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("pop3: read banner: %w", err)}
	}
	if !strings.HasPrefix(line, "+OK") {
		return ProbeResult{Err: fmt.Errorf("pop3: unexpected banner: %s", strings.TrimSpace(line))}
	}

	// Send USER
	if _, err = fmt.Fprintf(conn, "USER %s\r\n", username); err != nil {
		return ProbeResult{Err: fmt.Errorf("pop3: send USER: %w", err)}
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("pop3: USER response: %w", err)}
	}
	if !strings.HasPrefix(line, "+OK") {
		return ProbeResult{Err: fmt.Errorf("pop3: USER rejected: %s", strings.TrimSpace(line)), AuthFail: true}
	}

	// Send PASS
	if _, err = fmt.Fprintf(conn, "PASS %s\r\n", password); err != nil {
		return ProbeResult{Err: fmt.Errorf("pop3: send PASS: %w", err)}
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("pop3: PASS response: %w", err)}
	}
	if strings.HasPrefix(line, "+OK") {
		return ProbeResult{Success: true}
	}
	return ProbeResult{Err: fmt.Errorf("pop3: auth failed: %s", strings.TrimSpace(line)), AuthFail: true}
}

// ─── IMAP ─────────────────────────────────────────────────────────────────────

// IMAPProber tests IMAP credentials (RFC 3501).
type IMAPProber struct{}

func (p *IMAPProber) Name() string     { return "imap" }
func (p *IMAPProber) DefaultPort() int { return 143 }

func (p *IMAPProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	reader := bufio.NewReader(conn)

	// Read banner (* OK ...)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("imap: read banner: %w", err)}
	}
	if !strings.HasPrefix(line, "* OK") && !strings.HasPrefix(line, "* ok") {
		return ProbeResult{Err: fmt.Errorf("imap: unexpected banner: %s", strings.TrimSpace(line))}
	}

	// Send LOGIN command
	cmd := fmt.Sprintf("a1 LOGIN %s %s\r\n", imapQuote(username), imapQuote(password))
	if _, err = conn.Write([]byte(cmd)); err != nil {
		return ProbeResult{Err: fmt.Errorf("imap: send LOGIN: %w", err)}
	}

	// Read response (may have untagged lines before tagged response)
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return ProbeResult{Err: fmt.Errorf("imap: read response: %w", err)}
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "a1 OK") || strings.HasPrefix(line, "a1 ok") {
			return ProbeResult{Success: true}
		}
		if strings.HasPrefix(line, "a1 NO") || strings.HasPrefix(line, "a1 no") ||
			strings.HasPrefix(line, "a1 BAD") || strings.HasPrefix(line, "a1 bad") {
			return ProbeResult{Err: fmt.Errorf("imap: auth failed: %s", line), AuthFail: true}
		}
		// Untagged response, continue reading
	}
}

// imapQuote quotes a string for use in IMAP commands.
func imapQuote(s string) string {
	needsQuote := false
	for _, c := range s {
		if c == '"' || c == '\\' || c == '\r' || c == '\n' || c == '{' || c == '}' {
			needsQuote = true
			break
		}
	}
	if needsQuote {
		var sb strings.Builder
		sb.WriteByte('"')
		for _, c := range s {
			if c == '"' || c == '\\' {
				sb.WriteByte('\\')
			}
			sb.WriteRune(c)
		}
		sb.WriteByte('"')
		return sb.String()
	}
	return `"` + s + `"`
}

// ─── VNC ──────────────────────────────────────────────────────────────────────

// VNCProber tests VNC credentials using the RFB protocol.
type VNCProber struct{}

func (p *VNCProber) Name() string     { return "vnc" }
func (p *VNCProber) DefaultPort() int { return 5900 }

func (p *VNCProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Read server version (12 bytes: "RFB XXX.YYY\n")
	verBuf := make([]byte, 12)
	if _, err = io.ReadFull(conn, verBuf); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: read version: %w", err)}
	}
	serverVer := string(verBuf)
	if !strings.HasPrefix(serverVer, "RFB ") {
		return ProbeResult{Err: fmt.Errorf("vnc: not an RFB server")}
	}

	// Reply with our version
	if _, err = conn.Write([]byte("RFB 003.008\n")); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: send version: %w", err)}
	}

	// Determine if this is protocol version 3.3
	isV33 := false
	if len(serverVer) >= 11 {
		parts := strings.Split(strings.TrimSpace(serverVer), ".")
		if len(parts) == 2 {
			minor := parts[1]
			if minor < "007" {
				isV33 = true
			}
		}
	}

	if isV33 {
		secBuf := make([]byte, 4)
		if _, err = io.ReadFull(conn, secBuf); err != nil {
			return ProbeResult{Err: fmt.Errorf("vnc: read security type: %w", err)}
		}
		secType := binary.BigEndian.Uint32(secBuf)
		if secType == 0 {
			errLenBuf := make([]byte, 4)
			if _, err = io.ReadFull(conn, errLenBuf); err != nil {
				return ProbeResult{Err: fmt.Errorf("vnc: read error len: %w", err)}
			}
			errLen := binary.BigEndian.Uint32(errLenBuf)
			if errLen > 1024 {
				errLen = 1024
			}
			errMsg := make([]byte, errLen)
			_, _ = io.ReadFull(conn, errMsg)
			return ProbeResult{Err: fmt.Errorf("vnc: server error: %s", string(errMsg))}
		}
		if secType == 1 {
			return ProbeResult{Success: true}
		}
		if secType == 2 {
			return vncDoAuth(conn, password)
		}
		return ProbeResult{Err: fmt.Errorf("vnc: unsupported security type %d", secType)}
	}

	// RFB 3.7+: read security type list
	countBuf := make([]byte, 1)
	if _, err = io.ReadFull(conn, countBuf); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: read security count: %w", err)}
	}
	count := int(countBuf[0])
	if count == 0 {
		errLenBuf := make([]byte, 4)
		if _, err = io.ReadFull(conn, errLenBuf); err != nil {
			return ProbeResult{Err: fmt.Errorf("vnc: read error len: %w", err)}
		}
		errLen := binary.BigEndian.Uint32(errLenBuf)
		if errLen > 1024 {
			errLen = 1024
		}
		errMsg := make([]byte, errLen)
		_, _ = io.ReadFull(conn, errMsg)
		return ProbeResult{Err: fmt.Errorf("vnc: server error: %s", string(errMsg))}
	}

	secTypes := make([]byte, count)
	if _, err = io.ReadFull(conn, secTypes); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: read security types: %w", err)}
	}

	hasVNCAuth := false
	hasNone := false
	for _, t := range secTypes {
		if t == 2 {
			hasVNCAuth = true
		}
		if t == 1 {
			hasNone = true
		}
	}

	if hasVNCAuth {
		if _, err = conn.Write([]byte{2}); err != nil {
			return ProbeResult{Err: fmt.Errorf("vnc: select VNC auth: %w", err)}
		}
		return vncDoAuth(conn, password)
	}
	if hasNone {
		if _, err = conn.Write([]byte{1}); err != nil {
			return ProbeResult{Err: fmt.Errorf("vnc: select None auth: %w", err)}
		}
		resBuf := make([]byte, 4)
		if _, err = io.ReadFull(conn, resBuf); err != nil {
			return ProbeResult{Success: true}
		}
		if binary.BigEndian.Uint32(resBuf) == 0 {
			return ProbeResult{Success: true}
		}
		return ProbeResult{Err: fmt.Errorf("vnc: None auth failed"), AuthFail: false}
	}

	return ProbeResult{Err: fmt.Errorf("vnc: no supported security types")}
}

func vncDoAuth(conn net.Conn, password string) ProbeResult {
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: read challenge: %w", err)}
	}

	key := make([]byte, 8)
	pwBytes := []byte(password)
	for i := 0; i < 8 && i < len(pwBytes); i++ {
		key[i] = vncBitReverse(pwBytes[i])
	}

	response, err := vncDESEncrypt(key, challenge)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: DES encrypt: %w", err)}
	}

	if _, err = conn.Write(response); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: send response: %w", err)}
	}

	resBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, resBuf); err != nil {
		return ProbeResult{Err: fmt.Errorf("vnc: read auth result: %w", err)}
	}
	result := binary.BigEndian.Uint32(resBuf)
	switch result {
	case 0:
		return ProbeResult{Success: true}
	case 1:
		return ProbeResult{Err: fmt.Errorf("vnc: authentication failed"), AuthFail: true}
	case 2:
		return ProbeResult{Err: fmt.Errorf("vnc: too many authentication failures"), AuthFail: true}
	default:
		return ProbeResult{Err: fmt.Errorf("vnc: unknown auth result %d", result), AuthFail: true}
	}
}

func vncBitReverse(b byte) byte {
	b = (b&0x55)<<1 | (b>>1)&0x55
	b = (b&0x33)<<2 | (b>>2)&0x33
	b = (b&0x0F)<<4 | (b>>4)&0x0F
	return b
}

func vncDESEncrypt(key, challenge []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	response := make([]byte, 16)
	block.Encrypt(response[0:8], challenge[0:8])
	block.Encrypt(response[8:16], challenge[8:16])
	return response, nil
}

// ─── MSSQL ────────────────────────────────────────────────────────────────────

// MSSQLProber tests Microsoft SQL Server credentials using TDS protocol.
type MSSQLProber struct{}

func (p *MSSQLProber) Name() string     { return "mssql" }
func (p *MSSQLProber) DefaultPort() int { return 1433 }

func (p *MSSQLProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	preLogin := buildMSSQLPreLogin()
	if _, err = conn.Write(preLogin); err != nil {
		return ProbeResult{Err: fmt.Errorf("mssql: send pre-login: %w", err)}
	}

	hdr := make([]byte, 8)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return ProbeResult{Err: fmt.Errorf("mssql: read pre-login response header: %w", err)}
	}
	respLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if respLen > 8 {
		discard := make([]byte, respLen-8)
		_, _ = io.ReadFull(conn, discard)
	}

	login7 := buildMSSQLLogin7(host, username, password)
	if _, err = conn.Write(login7); err != nil {
		return ProbeResult{Err: fmt.Errorf("mssql: send login7: %w", err)}
	}

	return mssqlReadLoginResponse(conn)
}

func buildMSSQLPreLogin() []byte {
	payload := []byte{
		0x00, 0x00, 0x15, 0x00, 0x06,
		0x01, 0x00, 0x1B, 0x00, 0x01,
		0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0E, 0x00, 0x0B, 0xDE, 0x00, 0x00,
		0x02,
	}

	total := 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x12
	pkt[1] = 0x01
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x00
	pkt[7] = 0x00
	copy(pkt[8:], payload)
	return pkt
}

func buildMSSQLLogin7(host, username, password string) []byte {
	encodeUTF16LE := func(s string) []byte {
		runes := []rune(s)
		b := make([]byte, len(runes)*2)
		for i, r := range runes {
			b[i*2] = byte(r)
			b[i*2+1] = byte(r >> 8)
		}
		return b
	}

	obfuscatePassword := func(pwd string) []byte {
		pwdUTF16 := encodeUTF16LE(pwd)
		result := make([]byte, len(pwdUTF16))
		for i, b := range pwdUTF16 {
			b ^= 0xA5
			b = (b >> 4) | (b << 4)
			result[i] = b
		}
		return result
	}

	hostUTF16 := encodeUTF16LE(host)
	userUTF16 := encodeUTF16LE(username)
	pwdObf := obfuscatePassword(password)
	appUTF16 := encodeUTF16LE("AEGIS")
	serverUTF16 := encodeUTF16LE(host)
	dbUTF16 := encodeUTF16LE("master")
	ifaceUTF16 := encodeUTF16LE("ODBC")
	langUTF16 := encodeUTF16LE("")

	hostNameOff := uint16(94)
	hostNameLen := uint16(len(hostUTF16) / 2)
	userNameOff := hostNameOff + uint16(len(hostUTF16))
	userNameLen := uint16(len(userUTF16) / 2)
	passwordOff := userNameOff + uint16(len(userUTF16))
	passwordLen := uint16(len(pwdObf) / 2)
	appNameOff := passwordOff + uint16(len(pwdObf))
	appNameLen := uint16(len(appUTF16) / 2)
	serverNameOff := appNameOff + uint16(len(appUTF16))
	serverNameLen := uint16(len(serverUTF16) / 2)
	ifaceOff := serverNameOff + uint16(len(serverUTF16))
	ifaceLen := uint16(len(ifaceUTF16) / 2)
	langOff := ifaceOff + uint16(len(ifaceUTF16))
	langLen := uint16(len(langUTF16) / 2)
	databaseOff := langOff + uint16(len(langUTF16))
	databaseLen := uint16(len(dbUTF16) / 2)

	var varData bytes.Buffer
	varData.Write(hostUTF16)
	varData.Write(userUTF16)
	varData.Write(pwdObf)
	varData.Write(appUTF16)
	varData.Write(serverUTF16)
	varData.Write(ifaceUTF16)
	varData.Write(langUTF16)
	varData.Write(dbUTF16)

	totalLen := 94 + varData.Len()

	var buf bytes.Buffer
	buf.WriteByte(0x10)
	buf.WriteByte(0x01)
	_ = binary.Write(&buf, binary.BigEndian, uint16(totalLen+8))
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	_ = binary.Write(&buf, binary.LittleEndian, uint32(totalLen))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x74000004))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(4096))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x07000000))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1234))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.WriteByte(0xE0)
	buf.WriteByte(0x03)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0409))

	_ = binary.Write(&buf, binary.LittleEndian, hostNameOff)
	_ = binary.Write(&buf, binary.LittleEndian, hostNameLen)
	_ = binary.Write(&buf, binary.LittleEndian, userNameOff)
	_ = binary.Write(&buf, binary.LittleEndian, userNameLen)
	_ = binary.Write(&buf, binary.LittleEndian, passwordOff)
	_ = binary.Write(&buf, binary.LittleEndian, passwordLen)
	_ = binary.Write(&buf, binary.LittleEndian, appNameOff)
	_ = binary.Write(&buf, binary.LittleEndian, appNameLen)
	_ = binary.Write(&buf, binary.LittleEndian, serverNameOff)
	_ = binary.Write(&buf, binary.LittleEndian, serverNameLen)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, ifaceOff)
	_ = binary.Write(&buf, binary.LittleEndian, ifaceLen)
	_ = binary.Write(&buf, binary.LittleEndian, langOff)
	_ = binary.Write(&buf, binary.LittleEndian, langLen)
	_ = binary.Write(&buf, binary.LittleEndian, databaseOff)
	_ = binary.Write(&buf, binary.LittleEndian, databaseLen)

	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	buf.Write(varData.Bytes())

	return buf.Bytes()
}

func mssqlReadLoginResponse(conn net.Conn) ProbeResult {
	for {
		hdr := make([]byte, 8)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return ProbeResult{Err: fmt.Errorf("mssql: read response header: %w", err)}
		}
		pktType := hdr[0]
		pktLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if pktLen < 8 {
			return ProbeResult{Err: fmt.Errorf("mssql: invalid packet length %d", pktLen)}
		}
		dataLen := pktLen - 8
		data := make([]byte, dataLen)
		if dataLen > 0 {
			if _, err := io.ReadFull(conn, data); err != nil {
				return ProbeResult{Err: fmt.Errorf("mssql: read response data: %w", err)}
			}
		}

		if pktType == 0x04 {
			i := 0
			for i < len(data) {
				token := data[i]
				i++
				switch token {
				case 0xAA:
					return ProbeResult{Success: true}
				case 0xAB:
					if i+2 > len(data) {
						return ProbeResult{Err: fmt.Errorf("mssql: truncated info token")}
					}
					msgLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
					i += 2 + msgLen
				case 0x79:
					i += 4
				case 0xFD, 0xFE, 0xFF:
					if i+8 > len(data) {
						return ProbeResult{Err: fmt.Errorf("mssql: auth failed"), AuthFail: true}
					}
					status := binary.LittleEndian.Uint16(data[i : i+2])
					if status&0x0002 != 0 {
						return ProbeResult{Err: fmt.Errorf("mssql: authentication failed"), AuthFail: true}
					}
					i += 8
				case 0xE3:
					if i+2 > len(data) {
						goto nextPkt
					}
					envLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
					i += 2 + envLen
				case 0x81:
					return ProbeResult{Success: true}
				default:
					goto nextPkt
				}
			}
		}
	nextPkt:
		if hdr[1]&0x01 != 0 {
			return ProbeResult{Err: fmt.Errorf("mssql: no login ack received"), AuthFail: true}
		}
	}
}

// ─── MongoDB ──────────────────────────────────────────────────────────────────

// MongoDBProber tests MongoDB credentials using SCRAM-SHA-1.
type MongoDBProber struct{}

func (p *MongoDBProber) Name() string     { return "mongodb" }
func (p *MongoDBProber) DefaultPort() int { return 27017 }

func (p *MongoDBProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	isMasterQuery := mongoMarshalDoc([]mongoKV{
		{Key: "isMaster", Val: int32(1)},
	})
	isMasterPkt := mongoMakeOpQuery("admin.$cmd", isMasterQuery)
	if _, err = conn.Write(isMasterPkt); err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: send isMaster: %w", err)}
	}

	_, isMasterResp, err := mongoReadReply(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: read isMaster: %w", err)}
	}
	doc := mongoParseBSON(isMasterResp)
	if ok, exists := doc["ok"]; !exists || mongoToFloat64(ok) != 1.0 {
		return ProbeResult{Err: fmt.Errorf("mongodb: isMaster failed")}
	}

	nonceBytes := make([]byte, 18)
	if _, err = rand.Read(nonceBytes); err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: generate nonce: %w", err)}
	}
	clientNonce := base64.StdEncoding.EncodeToString(nonceBytes)

	clientFirstBare := fmt.Sprintf("n=%s,r=%s", username, clientNonce)
	clientFirstMsg := "n,," + clientFirstBare

	saslStartDoc := mongoMarshalDoc([]mongoKV{
		{Key: "saslStart", Val: int32(1)},
		{Key: "mechanism", Val: "SCRAM-SHA-1"},
		{Key: "payload", Val: []byte(clientFirstMsg)},
		{Key: "options", Val: mongoMarshalDoc([]mongoKV{{Key: "skipEmptyExchange", Val: true}})},
	})
	saslStartPkt := mongoMakeOpQuery("admin.$cmd", saslStartDoc)
	if _, err = conn.Write(saslStartPkt); err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: send saslStart: %w", err)}
	}

	_, saslStartResp, err := mongoReadReply(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: read saslStart: %w", err)}
	}
	startDoc := mongoParseBSON(saslStartResp)
	if ok, exists := startDoc["ok"]; !exists || mongoToFloat64(ok) != 1.0 {
		errmsg, _ := startDoc["errmsg"].(string)
		return ProbeResult{Err: fmt.Errorf("mongodb: saslStart failed: %s", errmsg), AuthFail: true}
	}

	conversationId := int32(0)
	if cid, ok := startDoc["conversationId"]; ok {
		conversationId = mongoToInt32(cid)
	}

	var serverFirstMsg string
	if pl, ok := startDoc["payload"]; ok {
		switch v := pl.(type) {
		case []byte:
			serverFirstMsg = string(v)
		case string:
			serverFirstMsg = v
		}
	}

	sfmParts := make(map[string]string)
	for _, part := range strings.Split(serverFirstMsg, ",") {
		if idx := strings.IndexByte(part, '='); idx > 0 {
			sfmParts[part[:idx]] = part[idx+1:]
		}
	}
	serverNonce, saltB64, iterStr := sfmParts["r"], sfmParts["s"], sfmParts["i"]
	if serverNonce == "" || saltB64 == "" || iterStr == "" {
		return ProbeResult{Err: fmt.Errorf("mongodb: invalid server-first-message: %s", serverFirstMsg)}
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: decode salt: %w", err)}
	}

	iterations := 0
	for _, c := range iterStr {
		if c >= '0' && c <= '9' {
			iterations = iterations*10 + int(c-'0')
		}
	}
	if iterations == 0 {
		iterations = 10000
	}

	saltedPassword := pbkdf2.Key([]byte(password), salt, iterations, 20, sha1.New)

	mac := hmac.New(sha1.New, saltedPassword)
	mac.Write([]byte("Client Key"))
	clientKey := mac.Sum(nil)

	h := sha1.New() //nolint:gosec
	h.Write(clientKey)
	storedKey := h.Sum(nil)

	clientFinalWithoutProof := fmt.Sprintf("c=biws,r=%s", serverNonce)
	authMessage := clientFirstBare + "," + serverFirstMsg + "," + clientFinalWithoutProof

	mac2 := hmac.New(sha1.New, storedKey)
	mac2.Write([]byte(authMessage))
	clientSignature := mac2.Sum(nil)

	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	clientFinalMsg := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

	saslContDoc := mongoMarshalDoc([]mongoKV{
		{Key: "saslContinue", Val: int32(1)},
		{Key: "conversationId", Val: conversationId},
		{Key: "payload", Val: []byte(clientFinalMsg)},
	})
	saslContPkt := mongoMakeOpQuery("admin.$cmd", saslContDoc)
	if _, err = conn.Write(saslContPkt); err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: send saslContinue: %w", err)}
	}

	_, saslContResp, err := mongoReadReply(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("mongodb: read saslContinue: %w", err)}
	}
	contDoc := mongoParseBSON(saslContResp)
	if ok, exists := contDoc["ok"]; !exists || mongoToFloat64(ok) != 1.0 {
		errmsg, _ := contDoc["errmsg"].(string)
		return ProbeResult{Err: fmt.Errorf("mongodb: authentication failed: %s", errmsg), AuthFail: true}
	}

	return ProbeResult{Success: true}
}

// mongoKV is a key-value pair for ordered BSON document building.
type mongoKV struct {
	Key string
	Val interface{}
}

// mongoMarshalDoc serializes an ordered list of key-value pairs as BSON.
func mongoMarshalDoc(pairs []mongoKV) []byte {
	var body bytes.Buffer
	for _, kv := range pairs {
		switch v := kv.Val.(type) {
		case int32:
			body.WriteByte(0x10)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			_ = binary.Write(&body, binary.LittleEndian, v)
		case int64:
			body.WriteByte(0x12)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			_ = binary.Write(&body, binary.LittleEndian, v)
		case float64:
			body.WriteByte(0x01)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			_ = binary.Write(&body, binary.LittleEndian, v)
		case string:
			body.WriteByte(0x02)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			strBytes := []byte(v)
			_ = binary.Write(&body, binary.LittleEndian, int32(len(strBytes)+1))
			body.Write(strBytes)
			body.WriteByte(0)
		case bool:
			body.WriteByte(0x08)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			if v {
				body.WriteByte(1)
			} else {
				body.WriteByte(0)
			}
		case []byte:
			body.WriteByte(0x05)
			body.WriteString(kv.Key)
			body.WriteByte(0)
			_ = binary.Write(&body, binary.LittleEndian, int32(len(v)))
			body.WriteByte(0x00)
			body.Write(v)
		}
	}

	totalLen := int32(4 + body.Len() + 1)
	var doc bytes.Buffer
	_ = binary.Write(&doc, binary.LittleEndian, totalLen)
	doc.Write(body.Bytes())
	doc.WriteByte(0)
	return doc.Bytes()
}

// mongoMakeOpQuery builds a MongoDB OP_QUERY wire protocol message.
func mongoMakeOpQuery(collection string, query []byte) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, int32(0))
	body.WriteString(collection)
	body.WriteByte(0)
	_ = binary.Write(&body, binary.LittleEndian, int32(0))
	_ = binary.Write(&body, binary.LittleEndian, int32(-1))
	body.Write(query)

	totalLen := int32(16 + body.Len())
	var msg bytes.Buffer
	_ = binary.Write(&msg, binary.LittleEndian, totalLen)
	_ = binary.Write(&msg, binary.LittleEndian, int32(1))
	_ = binary.Write(&msg, binary.LittleEndian, int32(0))
	_ = binary.Write(&msg, binary.LittleEndian, int32(2004))
	msg.Write(body.Bytes())
	return msg.Bytes()
}

// mongoReadReply reads a MongoDB OP_REPLY and returns (flags, firstDocument, error).
func mongoReadReply(conn net.Conn) (int32, []byte, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, fmt.Errorf("read reply header: %w", err)
	}
	msgLen := int(binary.LittleEndian.Uint32(hdr[0:4]))
	if msgLen < 16 {
		return 0, nil, fmt.Errorf("reply too short: %d", msgLen)
	}
	body := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, fmt.Errorf("read reply body: %w", err)
	}
	if len(body) < 20 {
		return 0, nil, fmt.Errorf("reply body too short")
	}
	flags := int32(binary.LittleEndian.Uint32(body[0:4]))
	numReturned := int32(binary.LittleEndian.Uint32(body[16:20]))
	if numReturned < 1 {
		return flags, nil, fmt.Errorf("no documents in reply")
	}
	docs := body[20:]
	return flags, docs, nil
}

// mongoParseBSON parses a BSON document (the first one in the byte slice).
func mongoParseBSON(data []byte) map[string]interface{} {
	result := make(map[string]interface{})
	if len(data) < 5 {
		return result
	}
	docLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if docLen > len(data) {
		docLen = len(data)
	}
	i := 4
	for i < docLen-1 {
		if i >= len(data) {
			break
		}
		elemType := data[i]
		i++
		keyStart := i
		for i < len(data) && data[i] != 0 {
			i++
		}
		if i >= len(data) {
			break
		}
		key := string(data[keyStart:i])
		i++

		switch elemType {
		case 0x01:
			if i+8 > len(data) {
				return result
			}
			bits64 := binary.LittleEndian.Uint64(data[i : i+8])
			result[key] = mongoFloat64FromBits(bits64)
			i += 8
		case 0x02:
			if i+4 > len(data) {
				return result
			}
			strLen := int(binary.LittleEndian.Uint32(data[i : i+4]))
			i += 4
			if i+strLen > len(data) {
				return result
			}
			result[key] = string(data[i : i+strLen-1])
			i += strLen
		case 0x03:
			if i+4 > len(data) {
				return result
			}
			subDocLen := int(binary.LittleEndian.Uint32(data[i : i+4]))
			if i+subDocLen > len(data) {
				return result
			}
			result[key] = mongoParseBSON(data[i : i+subDocLen])
			i += subDocLen
		case 0x05:
			if i+5 > len(data) {
				return result
			}
			binLen := int(binary.LittleEndian.Uint32(data[i : i+4]))
			i += 4
			i++
			if i+binLen > len(data) {
				return result
			}
			result[key] = data[i : i+binLen]
			i += binLen
		case 0x08:
			if i >= len(data) {
				return result
			}
			result[key] = data[i] == 1
			i++
		case 0x10:
			if i+4 > len(data) {
				return result
			}
			result[key] = int32(binary.LittleEndian.Uint32(data[i : i+4]))
			i += 4
		case 0x12:
			if i+8 > len(data) {
				return result
			}
			result[key] = int64(binary.LittleEndian.Uint64(data[i : i+8]))
			i += 8
		default:
			return result
		}
	}
	return result
}

func mongoFloat64FromBits(b uint64) float64 {
	return *(*float64)(unsafe.Pointer(&b))
}

func mongoToFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case bool:
		if n {
			return 1.0
		}
		return 0.0
	}
	return 0.0
}

func mongoToInt32(v interface{}) int32 {
	switch n := v.(type) {
	case int32:
		return n
	case int64:
		return int32(n)
	case float64:
		return int32(n)
	}
	return 0
}

// ─── LDAP ─────────────────────────────────────────────────────────────────────

// LDAPProber tests LDAP credentials using Simple Bind.
type LDAPProber struct{}

func (p *LDAPProber) Name() string     { return "ldap" }
func (p *LDAPProber) DefaultPort() int { return 389 }

func (p *LDAPProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	bindReq := ldapBuildBindRequest(1, 3, username, password)
	if _, err = conn.Write(bindReq); err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: send bind request: %w", err)}
	}

	return ldapReadBindResponse(conn)
}

func ldapBERLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	} else if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func ldapBERInt(n int) []byte {
	var b []byte
	if n == 0 {
		b = []byte{0x00}
	} else {
		for n > 0 {
			b = append([]byte{byte(n)}, b...)
			n >>= 8
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
	}
	result := []byte{0x02}
	result = append(result, ldapBERLen(len(b))...)
	result = append(result, b...)
	return result
}

func ldapOctetString(tag byte, s string) []byte {
	b := []byte(s)
	result := []byte{tag}
	result = append(result, ldapBERLen(len(b))...)
	result = append(result, b...)
	return result
}

func ldapSeq(data []byte) []byte {
	result := []byte{0x30}
	result = append(result, ldapBERLen(len(data))...)
	result = append(result, data...)
	return result
}

func ldapBuildBindRequest(messageID, version int, username, password string) []byte {
	versionBytes := ldapBERInt(version)
	nameBytes := ldapOctetString(0x04, username)
	simpleBytes := ldapOctetString(0x80, password)

	bindReqBody := append(versionBytes, nameBytes...)
	bindReqBody = append(bindReqBody, simpleBytes...)

	bindReq := []byte{0x60}
	bindReq = append(bindReq, ldapBERLen(len(bindReqBody))...)
	bindReq = append(bindReq, bindReqBody...)

	msgIDBytes := ldapBERInt(messageID)
	msgBody := append(msgIDBytes, bindReq...)
	return ldapSeq(msgBody)
}

func ldapReadBindResponse(conn net.Conn) ProbeResult {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read response header: %w", err)}
	}
	if hdr[0] != 0x30 {
		return ProbeResult{Err: fmt.Errorf("ldap: expected SEQUENCE, got 0x%02x", hdr[0])}
	}

	msgLen, _, err := ldapReadBERLen(conn, hdr[1])
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read msg length: %w", err)}
	}

	msgData := make([]byte, msgLen)
	if _, err = io.ReadFull(conn, msgData); err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read message body: %w", err)}
	}

	i := 0
	if i >= len(msgData) || msgData[i] != 0x02 {
		return ProbeResult{Err: fmt.Errorf("ldap: expected INTEGER for messageID")}
	}
	i++
	idLen, idLenBytes, err := ldapReadBERLenFromBytes(msgData, i)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read messageID len")}
	}
	i += idLenBytes + idLen

	if i >= len(msgData) {
		return ProbeResult{Err: fmt.Errorf("ldap: message too short for BindResponse")}
	}
	if msgData[i] != 0x61 {
		return ProbeResult{Err: fmt.Errorf("ldap: expected BindResponse (0x61), got 0x%02x", msgData[i])}
	}
	i++
	brLen, brLenBytes, err := ldapReadBERLenFromBytes(msgData, i)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read BindResponse len")}
	}
	i += brLenBytes
	_ = brLen

	if i >= len(msgData) || msgData[i] != 0x0A {
		return ProbeResult{Err: fmt.Errorf("ldap: expected ENUMERATED for resultCode")}
	}
	i++
	rcLen, rcLenBytes, err := ldapReadBERLenFromBytes(msgData, i)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("ldap: read resultCode len")}
	}
	i += rcLenBytes
	if i+rcLen > len(msgData) {
		return ProbeResult{Err: fmt.Errorf("ldap: resultCode data out of bounds")}
	}
	resultCode := 0
	for j := 0; j < rcLen; j++ {
		resultCode = (resultCode << 8) | int(msgData[i+j])
	}

	if resultCode == 0 {
		return ProbeResult{Success: true}
	}
	if resultCode == 49 {
		return ProbeResult{Err: fmt.Errorf("ldap: invalid credentials"), AuthFail: true}
	}
	return ProbeResult{Err: fmt.Errorf("ldap: bind failed with code %d", resultCode), AuthFail: resultCode == 49}
}

func ldapReadBERLen(conn net.Conn, firstByte byte) (int, int, error) {
	if firstByte < 0x80 {
		return int(firstByte), 1, nil
	}
	numBytes := int(firstByte & 0x7F)
	if numBytes > 4 {
		return 0, 1, fmt.Errorf("BER length too long")
	}
	lenBytes := make([]byte, numBytes)
	if _, err := io.ReadFull(conn, lenBytes); err != nil {
		return 0, 1 + numBytes, err
	}
	length := 0
	for _, b := range lenBytes {
		length = (length << 8) | int(b)
	}
	return length, 1 + numBytes, nil
}

func ldapReadBERLenFromBytes(data []byte, i int) (length int, bytesRead int, err error) {
	if i >= len(data) {
		return 0, 0, fmt.Errorf("BER length: out of bounds")
	}
	firstByte := data[i]
	if firstByte < 0x80 {
		return int(firstByte), 1, nil
	}
	numBytes := int(firstByte & 0x7F)
	if i+1+numBytes > len(data) {
		return 0, 1, fmt.Errorf("BER length: data truncated")
	}
	length = 0
	for j := 0; j < numBytes; j++ {
		length = (length << 8) | int(data[i+1+j])
	}
	return length, 1 + numBytes, nil
}

func ldapBERLenBytes(firstByte byte) int {
	if firstByte < 0x80 {
		return 1
	}
	return 1 + int(firstByte&0x7F)
}

// ─── SMB ──────────────────────────────────────────────────────────────────────

// SMBProber tests SMB credentials using SMB2 + NTLMv2 authentication.
type SMBProber struct{}

func (p *SMBProber) Name() string     { return "smb" }
func (p *SMBProber) DefaultPort() int { return 445 }

func (p *SMBProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	negReq := smbBuildNegotiate()
	if _, err = conn.Write(negReq); err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: send negotiate: %w", err)}
	}

	negResp, err := smbReadPacket(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: read negotiate response: %w", err)}
	}
	if len(negResp) < 64 {
		return ProbeResult{Err: fmt.Errorf("smb: negotiate response too short")}
	}
	negStatus := binary.LittleEndian.Uint32(negResp[8:12])
	if negStatus != 0 {
		return ProbeResult{Err: fmt.Errorf("smb: negotiate failed: status 0x%08X", negStatus)}
	}

	ntlmNeg := smbBuildNTLMNegotiate()
	setup1Req := smbBuildSessionSetup(0, ntlmNeg, 0)
	if _, err = conn.Write(setup1Req); err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: send session setup 1: %w", err)}
	}

	setup1Resp, err := smbReadPacket(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: read session setup 1 response: %w", err)}
	}
	if len(setup1Resp) < 64 {
		return ProbeResult{Err: fmt.Errorf("smb: session setup 1 response too short")}
	}
	setup1Status := binary.LittleEndian.Uint32(setup1Resp[8:12])
	if setup1Status != 0xC0000016 {
		return ProbeResult{Err: fmt.Errorf("smb: unexpected session setup 1 status: 0x%08X", setup1Status)}
	}

	sessionID := binary.LittleEndian.Uint64(setup1Resp[40:48])

	if len(setup1Resp) < 72 {
		return ProbeResult{Err: fmt.Errorf("smb: session setup 1 response too short for body")}
	}
	secBufOffset := int(binary.LittleEndian.Uint16(setup1Resp[68:70]))
	secBufLen := int(binary.LittleEndian.Uint16(setup1Resp[70:72]))
	if secBufOffset+secBufLen > len(setup1Resp) {
		return ProbeResult{Err: fmt.Errorf("smb: security buffer out of bounds")}
	}
	ntlmChallenge := setup1Resp[secBufOffset : secBufOffset+secBufLen]

	serverChallenge, targetInfo, err := smbParseNTLMChallenge(ntlmChallenge)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: parse NTLM challenge: %w", err)}
	}

	ntlmAuth, err := smbBuildNTLMAuthenticate(username, password, "", serverChallenge, targetInfo)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: build NTLM authenticate: %w", err)}
	}

	setup2Req := smbBuildSessionSetup(sessionID, ntlmAuth, 1)
	if _, err = conn.Write(setup2Req); err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: send session setup 2: %w", err)}
	}

	setup2Resp, err := smbReadPacket(conn)
	if err != nil {
		return ProbeResult{Err: fmt.Errorf("smb: read session setup 2 response: %w", err)}
	}
	if len(setup2Resp) < 64 {
		return ProbeResult{Err: fmt.Errorf("smb: session setup 2 response too short")}
	}
	setup2Status := binary.LittleEndian.Uint32(setup2Resp[8:12])
	switch setup2Status {
	case 0x00000000:
		return ProbeResult{Success: true}
	case 0xC000006D:
		return ProbeResult{Err: fmt.Errorf("smb: logon failure"), AuthFail: true}
	case 0xC0000022:
		return ProbeResult{Err: fmt.Errorf("smb: access denied"), AuthFail: true}
	case 0xC000006E:
		return ProbeResult{Err: fmt.Errorf("smb: account restriction"), AuthFail: true}
	default:
		return ProbeResult{Err: fmt.Errorf("smb: session setup failed: 0x%08X", setup2Status), AuthFail: false}
	}
}

func smbReadPacket(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read NetBIOS header: %w", err)
	}
	msgLen := int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("read SMB packet body: %w", err)
	}
	return data, nil
}

func smbBuildSMB2Header(command uint16, messageID, sessionID uint64) []byte {
	hdr := make([]byte, 64)
	copy(hdr[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint16(hdr[6:8], 0)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint16(hdr[12:14], command)
	binary.LittleEndian.PutUint16(hdr[14:16], 1)
	binary.LittleEndian.PutUint32(hdr[16:20], 0)
	binary.LittleEndian.PutUint32(hdr[20:24], 0)
	binary.LittleEndian.PutUint64(hdr[24:32], messageID)
	binary.LittleEndian.PutUint32(hdr[32:36], 0)
	binary.LittleEndian.PutUint32(hdr[36:40], 0)
	binary.LittleEndian.PutUint64(hdr[40:48], sessionID)
	return hdr
}

func smbBuildNegotiate() []byte {
	smb2Hdr := smbBuildSMB2Header(0, 0, 0)

	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, uint16(36))
	_ = binary.Write(&body, binary.LittleEndian, uint16(1))
	_ = binary.Write(&body, binary.LittleEndian, uint16(1))
	_ = binary.Write(&body, binary.LittleEndian, uint16(0))
	_ = binary.Write(&body, binary.LittleEndian, uint32(0))
	guid := make([]byte, 16)
	_, _ = rand.Read(guid)
	body.Write(guid)
	_ = binary.Write(&body, binary.LittleEndian, uint32(0))
	_ = binary.Write(&body, binary.LittleEndian, uint16(0))
	_ = binary.Write(&body, binary.LittleEndian, uint16(0))
	_ = binary.Write(&body, binary.LittleEndian, uint16(0x0202))

	smb2Pkt := append(smb2Hdr, body.Bytes()...)

	netbios := make([]byte, 4)
	netbios[0] = 0x00
	netbios[1] = byte(len(smb2Pkt) >> 16)
	netbios[2] = byte(len(smb2Pkt) >> 8)
	netbios[3] = byte(len(smb2Pkt))
	return append(netbios, smb2Pkt...)
}

func smbBuildNTLMNegotiate() []byte {
	var msg bytes.Buffer
	msg.WriteString("NTLMSSP\x00")
	_ = binary.Write(&msg, binary.LittleEndian, uint32(1))
	_ = binary.Write(&msg, binary.LittleEndian, uint32(0x60088215))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, uint32(40))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, uint32(40))
	msg.Write([]byte{0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F})
	return msg.Bytes()
}

func smbBuildSessionSetup(sessionID uint64, securityBuffer []byte, msgID uint64) []byte {
	smb2Hdr := smbBuildSMB2Header(1, msgID, sessionID)

	secBufOffset := uint16(64 + 24)
	var body bytes.Buffer
	_ = binary.Write(&body, binary.LittleEndian, uint16(25))
	body.WriteByte(0)
	body.WriteByte(1)
	_ = binary.Write(&body, binary.LittleEndian, uint32(0))
	_ = binary.Write(&body, binary.LittleEndian, uint32(0))
	_ = binary.Write(&body, binary.LittleEndian, secBufOffset)
	_ = binary.Write(&body, binary.LittleEndian, uint16(len(securityBuffer)))
	_ = binary.Write(&body, binary.LittleEndian, uint64(0))
	body.Write(securityBuffer)

	smb2Pkt := append(smb2Hdr, body.Bytes()...)

	netbios := make([]byte, 4)
	netbios[0] = 0x00
	netbios[1] = byte(len(smb2Pkt) >> 16)
	netbios[2] = byte(len(smb2Pkt) >> 8)
	netbios[3] = byte(len(smb2Pkt))
	return append(netbios, smb2Pkt...)
}

func smbParseNTLMChallenge(data []byte) ([]byte, []byte, error) {
	if len(data) < 32 {
		return nil, nil, fmt.Errorf("NTLM challenge too short")
	}
	if !bytes.HasPrefix(data, []byte("NTLMSSP\x00")) {
		return nil, nil, fmt.Errorf("not an NTLMSSP message")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 2 {
		return nil, nil, fmt.Errorf("expected NTLM CHALLENGE (type 2), got %d", msgType)
	}
	if len(data) < 48 {
		return nil, nil, fmt.Errorf("NTLM challenge too short for server challenge")
	}
	serverChallenge := data[24:32]

	if len(data) < 48 {
		return serverChallenge, nil, nil
	}
	tiLen := int(binary.LittleEndian.Uint16(data[40:42]))
	tiOffset := int(binary.LittleEndian.Uint32(data[44:48]))
	var targetInfo []byte
	if tiLen > 0 && tiOffset+tiLen <= len(data) {
		targetInfo = data[tiOffset : tiOffset+tiLen]
	}
	return serverChallenge, targetInfo, nil
}

func smbBuildNTLMAuthenticate(username, password, domain string, serverChallenge, targetInfo []byte) ([]byte, error) {
	pwdUTF16 := utf16.Encode([]rune(password))
	pwdBytes := make([]byte, len(pwdUTF16)*2)
	for i, w := range pwdUTF16 {
		binary.LittleEndian.PutUint16(pwdBytes[i*2:], w)
	}
	ntHash := md4Hash(pwdBytes)

	userDomain := strings.ToUpper(username) + domain
	userDomainUTF16 := utf16.Encode([]rune(userDomain))
	userDomainBytes := make([]byte, len(userDomainUTF16)*2)
	for i, w := range userDomainUTF16 {
		binary.LittleEndian.PutUint16(userDomainBytes[i*2:], w)
	}
	mac := hmac.New(md5.New, ntHash[:])
	mac.Write(userDomainBytes)
	responseKeyNT := mac.Sum(nil)

	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}

	timestamp := uint64(time.Now().UnixNano()/100) + 116444736000000000

	var blobBody bytes.Buffer
	_ = binary.Write(&blobBody, binary.LittleEndian, uint32(0x00000101))
	_ = binary.Write(&blobBody, binary.LittleEndian, uint32(0x00000000))
	_ = binary.Write(&blobBody, binary.LittleEndian, timestamp)
	blobBody.Write(clientChallenge)
	_ = binary.Write(&blobBody, binary.LittleEndian, uint32(0x00000000))
	if len(targetInfo) > 0 {
		blobBody.Write(targetInfo)
	}
	_ = binary.Write(&blobBody, binary.LittleEndian, uint32(0x00000000))

	mac2 := hmac.New(md5.New, responseKeyNT)
	mac2.Write(serverChallenge)
	mac2.Write(blobBody.Bytes())
	ntProofStr := mac2.Sum(nil)

	ntlmv2Response := append(ntProofStr, blobBody.Bytes()...)

	lmResponse := make([]byte, 24)

	encodeUTF16LE := func(s string) []byte {
		r := utf16.Encode([]rune(s))
		b := make([]byte, len(r)*2)
		for i, w := range r {
			binary.LittleEndian.PutUint16(b[i*2:], w)
		}
		return b
	}

	domainBytes := encodeUTF16LE(domain)
	userBytes := encodeUTF16LE(username)
	workstationBytes := encodeUTF16LE("")

	baseOffset := uint32(72)
	lmOffset := baseOffset
	ntOffset := lmOffset + uint32(len(lmResponse))
	domainOffset := ntOffset + uint32(len(ntlmv2Response))
	userOffset := domainOffset + uint32(len(domainBytes))
	workstationOffset := userOffset + uint32(len(userBytes))
	sessionKeyOffset := workstationOffset + uint32(len(workstationBytes))

	var msg bytes.Buffer
	msg.WriteString("NTLMSSP\x00")
	_ = binary.Write(&msg, binary.LittleEndian, uint32(3))

	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(lmResponse)))
	_ = binary.Write(&msg, binary.LittleEndian, lmOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(ntlmv2Response)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(ntlmv2Response)))
	_ = binary.Write(&msg, binary.LittleEndian, ntOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, domainOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, userOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(workstationBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(workstationBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, workstationOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(0))
	_ = binary.Write(&msg, binary.LittleEndian, sessionKeyOffset)

	_ = binary.Write(&msg, binary.LittleEndian, uint32(0x60088215))

	msg.Write(lmResponse)
	msg.Write(ntlmv2Response)
	msg.Write(domainBytes)
	msg.Write(userBytes)
	msg.Write(workstationBytes)

	return msg.Bytes(), nil
}

// md4Hash computes MD4 hash of data (RFC 1320 inline implementation).
func md4Hash(data []byte) [16]byte {
	a0 := uint32(0x67452301)
	b0 := uint32(0xEFCDAB89)
	c0 := uint32(0x98BADCFE)
	d0 := uint32(0x10325476)

	origLen := len(data)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0x00)
	}
	bitLen := uint64(origLen) * 8
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], bitLen)
	data = append(data, lenBytes[:]...)

	for i := 0; i < len(data); i += 64 {
		block := data[i : i+64]
		var X [16]uint32
		for j := 0; j < 16; j++ {
			X[j] = binary.LittleEndian.Uint32(block[j*4 : j*4+4])
		}

		aa, bb, cc, dd := a0, b0, c0, d0

		f := func(b, c, d uint32) uint32 { return (b & c) | (^b & d) }
		for idx := 0; idx < 16; idx++ {
			s := [4]uint32{3, 7, 11, 19}[idx%4]
			switch idx % 4 {
			case 0:
				aa = bits.RotateLeft32(aa+f(bb, cc, dd)+X[idx], int(s))
			case 1:
				dd = bits.RotateLeft32(dd+f(aa, bb, cc)+X[idx], int(s))
			case 2:
				cc = bits.RotateLeft32(cc+f(dd, aa, bb)+X[idx], int(s))
			case 3:
				bb = bits.RotateLeft32(bb+f(cc, dd, aa)+X[idx], int(s))
			}
		}

		g := func(b, c, d uint32) uint32 { return (b & c) | (b & d) | (c & d) }
		r2idx := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i2, idx := range r2idx {
			s := [4]uint32{3, 5, 9, 13}[i2%4]
			switch i2 % 4 {
			case 0:
				aa = bits.RotateLeft32(aa+g(bb, cc, dd)+X[idx]+0x5A827999, int(s))
			case 1:
				dd = bits.RotateLeft32(dd+g(aa, bb, cc)+X[idx]+0x5A827999, int(s))
			case 2:
				cc = bits.RotateLeft32(cc+g(dd, aa, bb)+X[idx]+0x5A827999, int(s))
			case 3:
				bb = bits.RotateLeft32(bb+g(cc, dd, aa)+X[idx]+0x5A827999, int(s))
			}
		}

		h := func(b, c, d uint32) uint32 { return b ^ c ^ d }
		r3idx := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i3, idx := range r3idx {
			s := [4]uint32{3, 9, 11, 15}[i3%4]
			switch i3 % 4 {
			case 0:
				aa = bits.RotateLeft32(aa+h(bb, cc, dd)+X[idx]+0x6ED9EBA1, int(s))
			case 1:
				dd = bits.RotateLeft32(dd+h(aa, bb, cc)+X[idx]+0x6ED9EBA1, int(s))
			case 2:
				cc = bits.RotateLeft32(cc+h(dd, aa, bb)+X[idx]+0x6ED9EBA1, int(s))
			case 3:
				bb = bits.RotateLeft32(bb+h(cc, dd, aa)+X[idx]+0x6ED9EBA1, int(s))
			}
		}

		a0 += aa
		b0 += bb
		c0 += cc
		d0 += dd
	}

	var result [16]byte
	binary.LittleEndian.PutUint32(result[0:4], a0)
	binary.LittleEndian.PutUint32(result[4:8], b0)
	binary.LittleEndian.PutUint32(result[8:12], c0)
	binary.LittleEndian.PutUint32(result[12:16], d0)
	return result
}

// ─── 达梦数据库（DM8）────────────────────────────────────────────────────────────
//
// DM8 TCP 协议（端口 5236）认证流程：
//  1. 客户端发送 17 字节握手包（CONNECT 命令）
//  2. 服务器返回版本/连接信息
//  3. 客户端发送登录包（用户名 + MD5(密码) 大写十六进制）
//  4. 服务器返回 OK（第5字节=0x00）或错误码

type DaMengProber struct{}

func (p *DaMengProber) Name() string     { return "dameng" }
func (p *DaMengProber) DefaultPort() int { return 5236 }

func (p *DaMengProber) Probe(ctx context.Context, host string, port int, username, password string, timeoutMs int) ProbeResult {
	conn, err := dialWithTimeout(ctx, host, port, timeoutMs)
	if err != nil {
		return ProbeResult{Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Step 1：发送握手包（17 字节）——声明这是 DM 客户端
	//   [0:4]  包总长 = 17（0x11）
	//   [4:8]  包序号（全0）
	//   [8]    命令 0x68 = CONNECT
	//   [9:11] 协议版本 0x0001
	//   [11:]  保留
	handshake := [17]byte{
		0x00, 0x00, 0x00, 0x11,
		0x00, 0x00, 0x00, 0x00,
		0x68,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if _, err = conn.Write(handshake[:]); err != nil {
		return ProbeResult{Err: err}
	}

	// Step 2：读取服务器握手响应（含版本 + 服务器信息）
	srvBuf := make([]byte, 512)
	n, err := conn.Read(srvBuf)
	if err != nil || n < 4 {
		return ProbeResult{Err: fmt.Errorf("dameng: 握手无响应")}
	}
	// DM 服务器响应的第一字节为 0x00；非 DM 服务直接拒绝
	if srvBuf[0] != 0x00 {
		return ProbeResult{Err: fmt.Errorf("dameng: 非 DM 服务")}
	}

	// Step 3：构造登录包
	//   密码以 MD5(password) 大写十六进制字符串传输（32 字节 ASCII）
	passHash := md5.Sum([]byte(password)) //nolint:gosec
	passHex := strings.ToUpper(fmt.Sprintf("%x", passHash))

	uBytes := []byte(username)
	pBytes := []byte(passHex)

	// Body 布局：
	//   [0]      命令 = 0x01（LOGIN）
	//   [1:3]    保留
	//   [3:5]    用户名长度（2 字节 BE）
	//   [5:5+uL] 用户名
	//   [5+uL : 5+uL+2] 密码哈希长度（2 字节 BE）
	//   [...]    密码哈希（32 字节 ASCII）
	//   [end]    数据库名长度 = 0x0000（使用默认库 SYSDBA）
	body := make([]byte, 0, 8+len(uBytes)+len(pBytes))
	body = append(body, 0x01, 0x00, 0x00) // LOGIN cmd + reserved
	body = append(body, byte(len(uBytes)>>8), byte(len(uBytes)))
	body = append(body, uBytes...)
	body = append(body, byte(len(pBytes)>>8), byte(len(pBytes)))
	body = append(body, pBytes...)
	body = append(body, 0x00, 0x00) // 数据库名长度 = 0

	totalLen := uint32(4 + len(body))
	loginPkt := make([]byte, 4, 4+len(body))
	loginPkt[0] = byte(totalLen >> 24)
	loginPkt[1] = byte(totalLen >> 16)
	loginPkt[2] = byte(totalLen >> 8)
	loginPkt[3] = byte(totalLen)
	loginPkt = append(loginPkt, body...)

	if _, err = conn.Write(loginPkt); err != nil {
		return ProbeResult{Err: err}
	}

	// Step 4：读取认证响应
	//   DM8 成功响应：第5字节（index 4）= 0x00
	//   失败响应：第5字节为非零错误码，或包含 "用户名或密码无效" 等错误文本
	resp := make([]byte, 512)
	n, err = conn.Read(resp)
	if err != nil || n < 4 {
		return ProbeResult{Err: fmt.Errorf("dameng: 认证无响应"), AuthFail: true}
	}
	resp = resp[:n]

	// 成功判定：响应第5字节为 0x00（OK）
	if n >= 5 && resp[4] == 0x00 {
		return ProbeResult{Success: true}
	}
	return ProbeResult{Err: fmt.Errorf("dameng: 认证失败"), AuthFail: true}
}

// ─── Prober Registry ──────────────────────────────────────────────────────────

// Probers is the global registry of all built-in protocol probers.
// HTTPFormProber is handled separately because it requires per-invocation config.
var Probers = map[string]Prober{
	"ssh":        &SSHProber{},
	"ftp":        &FTPProber{},
	"http-basic": &HTTPBasicProber{},
	"mysql":      &MySQLProber{},
	"redis":      &RedisProber{},
	"postgresql": &PostgreSQLProber{},
	"telnet":     &TelnetProber{},
	"smtp":       &SMTPProber{},
	"pop3":       &POP3Prober{},
	"imap":       &IMAPProber{},
	"vnc":        &VNCProber{},
	"mssql":      &MSSQLProber{},
	"mongodb":    &MongoDBProber{},
	"ldap":       &LDAPProber{},
	"smb":        &SMBProber{},
	"dameng":     &DaMengProber{},
}
