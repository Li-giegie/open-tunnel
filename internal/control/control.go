// Package control 实现服务端控制面：对外提供 Web UI 和 REST API，
// 用于管理认证账户、路由表以及监控在线会话。数据面（转发）见 internal/core。
package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"open-tunnel/internal/core"
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
	return &Control{cfg: cfg}, nil
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

// Handler 返回带 Basic Auth 的根处理器，供 Serve 使用，也便于测试。
func (c *Control) Handler() http.Handler {
	return c.basicAuth(c.routes())
}

func (c *Control) basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || !constantTimeEqual(c.cfg.Username, username) || !constantTimeEqual(c.cfg.Password, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="open-tunnel control"`)
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

// userStore 返回数据面的账户存储；未开启认证时返回 nil。
func (c *Control) userStore() core.UserStore {
	return c.cfg.Server.UserStore
}

func (c *Control) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if _, err := w.Write(indexHTML); err != nil {
			log.Println(err)
		}
	})
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
