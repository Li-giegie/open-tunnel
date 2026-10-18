package control

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Println(err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Println(err)
		}
	}()
	return json.NewDecoder(r.Body).Decode(v)
}

type statusResp struct {
	Addr          string `json:"addr"`
	ControlAddr   string `json:"control_addr"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	AuthEnabled   bool   `json:"auth_enabled"`
	SessionCount  int    `json:"session_count"`
	RouteCount    int    `json:"route_count"`
	UserCount     int    `json:"user_count"`
}

func (c *Control) handleStatus(w http.ResponseWriter, _ *http.Request) {
	srv := c.cfg.Server
	var sessionCount, routeCount, userCount int
	srv.RangeSessions(func(uint64, string, *net.UDPAddr, time.Time, []net.IP) bool {
		sessionCount++
		return true
	})
	srv.RangeIPV4Route(func(*net.IPNet, net.IP) bool {
		routeCount++
		return true
	})
	if us := c.userStore(); us != nil {
		us.RangeAccounts(func(string) bool {
			userCount++
			return true
		})
	}
	writeJSON(w, http.StatusOK, statusResp{
		Addr:          srv.Addr(),
		ControlAddr:   c.cfg.Addr,
		UptimeSeconds: int64(srv.Uptime().Seconds()),
		AuthEnabled:   c.userStore() != nil,
		SessionCount:  sessionCount,
		RouteCount:    routeCount,
		UserCount:     userCount,
	})
}

type sessionResp struct {
	// sessionId 由 IPv4、端口和随机数拼成，可能超过 2^53，
	// JSON 数字在 JS 中会丢精度，因此序列化为字符串。
	SessionId   string   `json:"session_id"`
	Account     string   `json:"account"`
	Addr        string   `json:"addr"`
	LastActive  string   `json:"last_active"`
	IdleSeconds int64    `json:"idle_seconds"`
	TunnelIPs   []string `json:"tunnel_ips"`
}

func (c *Control) handleSessions(w http.ResponseWriter, _ *http.Request) {
	// 会话数据做快照，回调中不再触碰 core 的锁
	sessions := make([]sessionResp, 0)
	c.cfg.Server.RangeSessions(func(sessionId uint64, account string, addr *net.UDPAddr, updateTime time.Time, ips []net.IP) bool {
		tunnelIPs := make([]string, 0, len(ips))
		seen := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			s := ip.String()
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			tunnelIPs = append(tunnelIPs, s)
		}
		sessions = append(sessions, sessionResp{
			SessionId:   strconv.FormatUint(sessionId, 10),
			Account:     account,
			Addr:        addr.String(),
			LastActive:  updateTime.Format(time.RFC3339),
			IdleSeconds: int64(time.Since(updateTime).Seconds()),
			TunnelIPs:   tunnelIPs,
		})
		return true
	})
	writeJSON(w, http.StatusOK, map[string][]sessionResp{"sessions": sessions})
}

// handleRemoveSession 删除（踢下线）指定会话。
// RemoveSession 对不存在的会话是空操作，因此幂等删除统一返回 200。
func (c *Control) handleRemoveSession(w http.ResponseWriter, r *http.Request) {
	idParam := r.PathValue("sessionId")
	sessionId, err := strconv.ParseUint(idParam, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session id: "+idParam)
		return
	}
	c.cfg.Server.RemoveSession(sessionId)
	writeJSON(w, http.StatusOK, map[string]string{"session_id": idParam})
}

func (c *Control) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	accounts := make([]string, 0)
	if us := c.userStore(); us != nil {
		us.RangeAccounts(func(account string) bool {
			accounts = append(accounts, account)
			return true
		})
	}
	sort.Strings(accounts)
	writeJSON(w, http.StatusOK, map[string][]string{"accounts": accounts})
}

type userReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

func (c *Control) handleAddUser(w http.ResponseWriter, r *http.Request) {
	us := c.userStore()
	if us == nil {
		writeError(w, http.StatusBadRequest, "user authentication is disabled, start the server with --auth-memory")
		return
	}
	var req userReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Account == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "account and password are required")
		return
	}
	if err := us.AddUser(req.Account, req.Password); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"account": req.Account})
}

func (c *Control) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	us := c.userStore()
	if us == nil {
		writeError(w, http.StatusBadRequest, "user authentication is disabled, start the server with --auth-memory")
		return
	}
	account := r.PathValue("account")
	if account == "" {
		writeError(w, http.StatusBadRequest, "account is required")
		return
	}
	if err := us.RemoveUser(account); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account": account})
}

type routeReq struct {
	Dst string `json:"dst"`
	Via string `json:"via"`
}

type routeResp struct {
	Dst string `json:"dst"`
	Via string `json:"via"`
}

func (c *Control) handleListRoutes(w http.ResponseWriter, _ *http.Request) {
	routes := make([]routeResp, 0)
	c.cfg.Server.RangeIPV4Route(func(dst *net.IPNet, via net.IP) bool {
		routes = append(routes, routeResp{Dst: dst.String(), Via: via.String()})
		return true
	})
	writeJSON(w, http.StatusOK, map[string][]routeResp{"routes": routes})
}

func (c *Control) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var req routeReq
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	_, dst, err := net.ParseCIDR(req.Dst)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dst CIDR: "+req.Dst)
		return
	}
	via := net.ParseIP(req.Via)
	if via == nil || via.To4() == nil {
		writeError(w, http.StatusBadRequest, "invalid via IPv4: "+req.Via)
		return
	}
	if err = c.cfg.Server.AddIPV4Route(dst, via); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, routeResp{Dst: dst.String(), Via: via.String()})
}

func (c *Control) handleRemoveRoute(w http.ResponseWriter, r *http.Request) {
	dstParam := r.URL.Query().Get("dst")
	if dstParam == "" {
		writeError(w, http.StatusBadRequest, "dst is required")
		return
	}
	_, dst, err := net.ParseCIDR(dstParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dst CIDR: "+dstParam)
		return
	}
	if !c.cfg.Server.DelIPV4Route(dst) {
		writeError(w, http.StatusNotFound, "route not found: "+dst.String())
		return
	}
	writeJSON(w, http.StatusOK, routeResp{Dst: dst.String()})
}
