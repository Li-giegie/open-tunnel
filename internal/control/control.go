// Package control 实现服务端控制面：对外提供 Web UI 和 REST API，
// 用于管理认证账户、路由表以及监控在线会话。数据面（转发）见 internal/core。
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"open-tunnel/internal/core"
)

const (
	// sessionCookieName 会话 Cookie 名称。
	sessionCookieName = "open-tunnel-session"
	// sessionTTL 会话有效期，滑动续期：每次请求通过校验都会顺延。
	sessionTTL = 24 * time.Hour
)

type Cfg struct {
	Addr     string       // HTTP 监听地址
	Username string       // Basic Auth 用户名
	Password string       // Basic Auth 密码
	Server   *core.Server // 数据面服务端，控制操作直接作用于它
	CertFile string       // TLS 证书 PEM 文件，与 KeyFile 成对提供时启用 HTTPS
	KeyFile  string       // TLS 私钥 PEM 文件
}

type Control struct {
	cfg Cfg

	sessionsLock sync.Mutex
	sessions     map[string]time.Time // 会话令牌 -> 过期时间
}

func New(cfg Cfg) (*Control, error) {
	if cfg.Addr == "" {
		return nil, errors.New("control addr is empty")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("control username or password is empty")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, errors.New("control cert file and key file must be provided together")
	}
	if cfg.CertFile != "" {
		// 提前加载校验，证书缺失或不匹配在监听之前就报错
		if _, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile); err != nil {
			return nil, fmt.Errorf("load control TLS key pair: %w", err)
		}
	}
	if cfg.Server == nil {
		return nil, errors.New("control server is nil")
	}
	return &Control{cfg: cfg, sessions: make(map[string]time.Time)}, nil
}

// TLS 报告控制面是否以 HTTPS 方式运行。
func (c *Control) TLS() bool {
	return c.cfg.CertFile != ""
}

// Listen 同步建立 HTTP 监听，端口被占用等错误可立即返回给调用方。
func (c *Control) Listen() (net.Listener, error) {
	return net.Listen("tcp", c.cfg.Addr)
}

// Serve 在已建立的监听上提供控制面服务，配置了证书时以 HTTPS 方式运行，
// ctx 取消时优雅关闭。
func (c *Control) Serve(ln net.Listener, ctx context.Context) error {
	srv := &http.Server{Handler: c.Handler()}

	errDone := make(chan error, 1)
	go func() {
		defer close(errDone)
		var err error
		if c.TLS() {
			err = srv.ServeTLS(ln, c.cfg.CertFile, c.cfg.KeyFile)
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errDone <- err
			return
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errDone:
		if err == nil {
			return fmt.Errorf("control plane stopped unexpectedly")
		}
		return err
	}
}

// Handler 返回根处理器，供 Serve 使用，也便于测试。
// 登录页面与登录/登出接口不做认证，其余 /api/ 接口经会话 Cookie 保护。
func (c *Control) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(indexHTML); err != nil {
			log.Println(err)
		}
	})
	mux.HandleFunc("POST /api/login", c.handleLogin)
	mux.HandleFunc("POST /api/logout", c.handleLogout)
	mux.Handle("/api/", c.requireSession(c.routes()))
	return mux
}

// requireSession 校验会话 Cookie，未登录或已过期返回 401。
// 不返回 WWW-Authenticate 头：该头会让浏览器弹出原生 Basic Auth 对话框；
// 前端 fetch 收到 401 自行回到登录页。
func (c *Control) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !c.touchSession(cookie.Value) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// constantTimeEqual 恒定时间比较两个字符串，先做哈希再比较，
// 避免长度差异导致的时序泄漏。
func constantTimeEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// createSession 创建服务端会话并通过 Set-Cookie 下发令牌。
func (c *Control) createSession(w http.ResponseWriter) error {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := hex.EncodeToString(buf)
	c.sessionsLock.Lock()
	c.purgeSessionsLocked()
	c.sessions[token] = time.Now().Add(sessionTTL)
	c.sessionsLock.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true, // JS 不可读，防止 XSS 窃取
		Secure:   c.TLS(),
		SameSite: http.SameSiteStrictMode, // 顺带防 CSRF
	})
	return nil
}

// touchSession 校验会话并滑动续期，令牌为空、不存在或已过期时返回 false。
func (c *Control) touchSession(token string) bool {
	if token == "" {
		return false
	}
	c.sessionsLock.Lock()
	defer c.sessionsLock.Unlock()
	expiry, ok := c.sessions[token]
	if !ok || !time.Now().Before(expiry) {
		return false
	}
	c.sessions[token] = time.Now().Add(sessionTTL)
	return true
}

// deleteSession 注销会话并让浏览器 Cookie 失效。
func (c *Control) deleteSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		c.sessionsLock.Lock()
		delete(c.sessions, cookie.Value)
		c.sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.TLS(),
		SameSite: http.SameSiteStrictMode,
	})
}

// purgeSessionsLocked 清理过期会话，调用方需持有 sessionsLock。
func (c *Control) purgeSessionsLocked() {
	now := time.Now()
	for token, expiry := range c.sessions {
		if !now.Before(expiry) {
			delete(c.sessions, token)
		}
	}
}

// userStore 返回数据面的账户存储；未开启认证时返回 nil。
func (c *Control) userStore() core.UserStore {
	return c.cfg.Server.UserStore
}

func (c *Control) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", c.handleStatus)
	mux.HandleFunc("GET /api/sessions", c.handleSessions)
	mux.HandleFunc("DELETE /api/sessions/{sessionId}", c.handleRemoveSession)
	mux.HandleFunc("GET /api/users", c.handleListUsers)
	mux.HandleFunc("POST /api/users", c.handleAddUser)
	mux.HandleFunc("DELETE /api/users/{account}", c.handleRemoveUser)
	mux.HandleFunc("GET /api/routes", c.handleListRoutes)
	mux.HandleFunc("POST /api/routes", c.handleAddRoute)
	mux.HandleFunc("DELETE /api/routes", c.handleRemoveRoute)
	return mux
}
