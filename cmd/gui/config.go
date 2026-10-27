//go:build windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"open-tunnel/internal/core"
)

// Cfg 是 GUI 的持久化配置,字段与 core.CliCfg 一一对应,
// 时间类字段以秒存储,连接时转换为 time.Duration。
type Cfg struct {
	Addr          string `json:"addr"`
	Account       string `json:"account"`
	Password      string `json:"password"`
	KeepaliveSec  int    `json:"keepalive_sec"`
	TimeoutSec    int    `json:"timeout_sec"`
	InterfaceName string `json:"interface_name"`
	InterfaceAddr string `json:"interface_addr"`
	InterfaceMTU  int    `json:"interface_mtu"`
}

func defaultCfg() Cfg {
	return Cfg{
		Addr:          "127.0.0.1:9000",
		KeepaliveSec:  15,
		TimeoutSec:    120,
		InterfaceName: "tun0",
		InterfaceAddr: "192.168.10.1/24",
		InterfaceMTU:  1450,
	}
}

// ToCore 转换为 core.CliCfg。
func (c Cfg) ToCore() core.CliCfg {
	return core.CliCfg{
		Addr:          c.Addr,
		Account:       c.Account,
		Password:      c.Password,
		Keepalive:     time.Duration(c.KeepaliveSec) * time.Second,
		Timeout:       time.Duration(c.TimeoutSec) * time.Second,
		InterfaceName: c.InterfaceName,
		InterfaceAddr: c.InterfaceAddr,
		InterfaceMTU:  c.InterfaceMTU,
	}
}

// configPath 返回 %APPDATA%\open-tunnel\gui.json。
// 提权运行不改变 APPDATA,仍写入当前用户目录,避免写 exe 所在目录的权限问题。
func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "open-tunnel", "gui.json"), nil
}

// LoadConfig 读取配置;文件不存在或损坏时返回默认值。
func LoadConfig() Cfg {
	c := defaultCfg()
	p, err := configPath()
	if err != nil {
		return c
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return c
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return defaultCfg()
	}
	// 防御异常值
	if c.KeepaliveSec <= 0 {
		c.KeepaliveSec = 15
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 120
	}
	if c.InterfaceMTU == 0 {
		c.InterfaceMTU = 1450
	}
	return c
}

// SaveConfig 写入配置文件。
func SaveConfig(c Cfg) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}
