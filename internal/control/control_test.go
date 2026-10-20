package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"open-tunnel/internal/core"
)

func newTestControl(t *testing.T, us core.UserStore) *httptest.Server {
	t.Helper()
	srv := core.NewServer(core.SrvCfg{Addr: "127.0.0.1:9000", UserStore: us})
	ctl, err := New(Cfg{Addr: "127.0.0.1:8080", Username: "admin", Password: "secret", Server: srv})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(ctl.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// loginCookie 用正确账号登录并返回会话 Cookie。
func loginCookie(t *testing.T, ts *httptest.Server) *http.Cookie {
	t.Helper()
	req, err := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}
	var session *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	if session == nil {
		t.Fatalf("login: no %s cookie set", sessionCookieName)
	}
	if !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags wrong: HttpOnly=%v SameSite=%v", session.HttpOnly, session.SameSite)
	}
	return session
}

func doRequest(t *testing.T, method, url, body string, cookie *http.Cookie) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data)
}

func TestLoginSession(t *testing.T) {
	ts := newTestControl(t, nil)

	// 错误密码
	code, _ := doRequest(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"wrong"}`, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", code)
	}

	// 未登录访问 API
	code, _ = doRequest(t, "GET", ts.URL+"/api/status", "", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("no session: got %d, want 401", code)
	}
	// 401 不带 WWW-Authenticate 头，避免浏览器弹出原生 Basic Auth 对话框
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		_ = resp.Body.Close()
		t.Fatal("WWW-Authenticate header should not be set")
	}
	_ = resp.Body.Close()

	// 正确登录，带 Cookie 访问
	cookie := loginCookie(t, ts)
	code, body := doRequest(t, "GET", ts.URL+"/api/status", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("status with session: got %d %s, want 200", code, body)
	}

	// 登出后 Cookie 失效
	code, _ = doRequest(t, "POST", ts.URL+"/api/logout", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("logout: got %d, want 200", code)
	}
	code, _ = doRequest(t, "GET", ts.URL+"/api/status", "", cookie)
	if code != http.StatusUnauthorized {
		t.Fatalf("status after logout: got %d, want 401", code)
	}

	// 登录页面不设防，无需会话即可访问
	code, _ = doRequest(t, "GET", ts.URL+"/", "", nil)
	if code != http.StatusOK {
		t.Fatalf("index page without session: got %d, want 200", code)
	}
}

func TestUsersRoundTrip(t *testing.T) {
	ts := newTestControl(t, core.NewUserStoreMemory())
	cookie := loginCookie(t, ts)

	code, body := doRequest(t, "POST", ts.URL+"/api/users", `{"account":"alice","password":"pw"}`, cookie)
	if code != http.StatusCreated {
		t.Fatalf("add user: got %d %s, want 201", code, body)
	}
	code, body = doRequest(t, "POST", ts.URL+"/api/users", `{"account":"alice","password":"pw"}`, cookie)
	if code != http.StatusConflict {
		t.Fatalf("duplicate user: got %d %s, want 409", code, body)
	}
	code, body = doRequest(t, "GET", ts.URL+"/api/users", "", cookie)
	if code != http.StatusOK || !strings.Contains(body, `"alice"`) {
		t.Fatalf("list users: got %d %s, want 200 containing alice", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/users/alice", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("remove user: got %d %s, want 200", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/users/alice", "", cookie)
	if code != http.StatusNotFound {
		t.Fatalf("remove missing user: got %d %s, want 404", code, body)
	}
	code, body = doRequest(t, "GET", ts.URL+"/api/users", "", cookie)
	if code != http.StatusOK || strings.Contains(body, "alice") {
		t.Fatalf("list users after delete: got %d %s, want 200 without alice", code, body)
	}
}

func TestUsersAuthDisabled(t *testing.T) {
	ts := newTestControl(t, nil)
	cookie := loginCookie(t, ts)

	code, body := doRequest(t, "POST", ts.URL+"/api/users", `{"account":"alice","password":"pw"}`, cookie)
	if code != http.StatusBadRequest || !strings.Contains(body, "disabled") {
		t.Fatalf("add user without auth: got %d %s, want 400 disabled", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/users/alice", "", cookie)
	if code != http.StatusBadRequest {
		t.Fatalf("remove user without auth: got %d %s, want 400", code, body)
	}
	code, body = doRequest(t, "GET", ts.URL+"/api/users", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("list users without auth: got %d %s, want 200 empty", code, body)
	}
}

func TestRoutesRoundTrip(t *testing.T) {
	ts := newTestControl(t, nil)
	cookie := loginCookie(t, ts)

	code, body := doRequest(t, "POST", ts.URL+"/api/routes", `{"dst":"192.168.1.0/24","via":"10.20.0.2"}`, cookie)
	if code != http.StatusCreated {
		t.Fatalf("add route: got %d %s, want 201", code, body)
	}
	code, body = doRequest(t, "POST", ts.URL+"/api/routes", `{"dst":"192.168.1.0/24","via":"10.20.0.2"}`, cookie)
	if code != http.StatusCreated {
		t.Fatalf("add duplicate route should be idempotent: got %d %s, want 201", code, body)
	}
	code, body = doRequest(t, "POST", ts.URL+"/api/routes", `{"dst":"not-a-cidr","via":"10.20.0.2"}`, cookie)
	if code != http.StatusBadRequest {
		t.Fatalf("add invalid route: got %d %s, want 400", code, body)
	}
	code, body = doRequest(t, "POST", ts.URL+"/api/routes", `{"dst":"192.168.1.0/24","via":"::1"}`, cookie)
	if code != http.StatusBadRequest {
		t.Fatalf("add non-ipv4 via: got %d %s, want 400", code, body)
	}
	code, body = doRequest(t, "GET", ts.URL+"/api/routes", "", cookie)
	if code != http.StatusOK || !strings.Contains(body, `"192.168.1.0/24"`) {
		t.Fatalf("list routes: got %d %s, want 200 containing dst", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/routes?dst=192.168.1.0/24", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("remove route: got %d %s, want 200", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/routes?dst=192.168.1.0/24", "", cookie)
	if code != http.StatusNotFound {
		t.Fatalf("remove missing route: got %d %s, want 404", code, body)
	}
}

func TestStatusAndSessions(t *testing.T) {
	ts := newTestControl(t, core.NewUserStoreMemory())
	cookie := loginCookie(t, ts)

	_, _ = doRequest(t, "POST", ts.URL+"/api/users", `{"account":"alice","password":"pw"}`, cookie)
	_, _ = doRequest(t, "POST", ts.URL+"/api/routes", `{"dst":"192.168.1.0/24","via":"10.20.0.2"}`, cookie)

	code, body := doRequest(t, "GET", ts.URL+"/api/status", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("status: got %d %s, want 200", code, body)
	}
	var status struct {
		Addr         string `json:"addr"`
		AuthEnabled  bool   `json:"auth_enabled"`
		SessionCount int    `json:"session_count"`
		RouteCount   int    `json:"route_count"`
		UserCount    int    `json:"user_count"`
	}
	if err := json.Unmarshal([]byte(body), &status); err != nil {
		t.Fatal(err)
	}
	if status.Addr != "127.0.0.1:9000" || !status.AuthEnabled {
		t.Fatalf("status content wrong: %s", body)
	}
	if status.RouteCount != 1 || status.UserCount != 1 || status.SessionCount != 0 {
		t.Fatalf("status counts wrong: %+v", status)
	}

	code, body = doRequest(t, "GET", ts.URL+"/api/sessions", "", cookie)
	if code != http.StatusOK || !strings.Contains(body, `"sessions":[]`) {
		t.Fatalf("sessions: got %d %s, want 200 empty", code, body)
	}
	// 幂等删除：不存在的会话也返回 200；非法 id 返回 400
	code, body = doRequest(t, "DELETE", ts.URL+"/api/sessions/123", "", cookie)
	if code != http.StatusOK {
		t.Fatalf("remove missing session: got %d %s, want 200", code, body)
	}
	code, body = doRequest(t, "DELETE", ts.URL+"/api/sessions/abc", "", cookie)
	if code != http.StatusBadRequest {
		t.Fatalf("remove invalid session id: got %d %s, want 400", code, body)
	}

	code, _ = doRequest(t, "GET", ts.URL+"/", "", nil)
	if code != http.StatusOK {
		t.Fatalf("index page: got %d, want 200", code)
	}
}

// writeSelfSignedCert 生成自签证书和私钥 PEM 文件，返回路径。
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "open-tunnel-control-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(t.TempDir(), "cert.pem")
	keyFile = filepath.Join(t.TempDir(), "key.pem")
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err = os.WriteFile(certFile, certOut, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, keyOut, 0600); err != nil {
		t.Fatal(err)
	}
	return
}

func TestNewCertKeyMustPair(t *testing.T) {
	certFile, _ := writeSelfSignedCert(t)
	srv := core.NewServer(core.SrvCfg{})
	if _, err := New(Cfg{Addr: "127.0.0.1:8080", Username: "a", Password: "b", Server: srv, CertFile: certFile}); err == nil {
		t.Fatal("cert without key should error")
	}
}

func TestServeTLS(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srv := core.NewServer(core.SrvCfg{Addr: "127.0.0.1:9000"})
	ctl, err := New(Cfg{
		Addr: "127.0.0.1:0", Username: "admin", Password: "secret",
		Server: srv, CertFile: certFile, KeyFile: keyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ctl.TLS() {
		t.Fatal("TLS() should be true")
	}

	ln, err := ctl.Listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- ctl.Serve(ln, ctx) }()

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 测试用自签证书
	}}
	// HTTPS 下登录获取会话 Cookie，Secure 标志应启用
	loginReq, err := http.NewRequest("POST", "https://"+ln.Addr().String()+"/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	var session *http.Cookie
	for _, cookie := range loginResp.Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
		}
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK || session == nil {
		t.Fatalf("login over TLS: got %d, session cookie: %v", loginResp.StatusCode, session)
	}
	if !session.Secure {
		t.Fatal("session cookie must be Secure over TLS")
	}

	req, err := http.NewRequest("GET", "https://"+ln.Addr().String()+"/api/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("https status: got %d, want 200", resp.StatusCode)
	}
	if resp.TLS == nil {
		t.Fatal("response should be over TLS")
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down")
	}
}
