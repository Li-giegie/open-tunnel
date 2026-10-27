//go:build windows

// Package main 提供 open-tunnel 客户端的 Windows 图形界面(基于 lxn/walk)。
//
// 构建(需先生成 rsrc_windows_amd64.syso,见 gui.exe.manifest 说明):
//
//	go build -ldflags="-H windowsgui" -o bin/gui.exe ./cmd/gui
package main

import (
	"log"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

func main() {
	cfg := LoadConfig()
	log.SetFlags(log.LstdFlags)

	var mw *walk.MainWindow

	var addrLE, accountLE, passwordLE, ifaceNameLE, ifaceAddrLE *walk.LineEdit
	var mtuNE, keepaliveNE, timeoutNE *walk.NumberEdit
	var connectBtn, disconnectBtn *walk.PushButton
	var statusLbl *walk.Label
	var logTE *walk.TextEdit

	// 连接/断开按钮回调引用 tun/tray,它们在窗口创建后才构造,
	// 消息循环启动前完成赋值,因此闭包内引用是安全的。
	var tun *Tunnel
	var tray *Tray

	currentCfg := func() Cfg {
		return Cfg{
			Addr:          addrLE.Text(),
			Account:       accountLE.Text(),
			Password:      passwordLE.Text(),
			KeepaliveSec:  int(keepaliveNE.Value()),
			TimeoutSec:    int(timeoutNE.Value()),
			InterfaceName: ifaceNameLE.Text(),
			InterfaceAddr: ifaceAddrLE.Text(),
			InterfaceMTU:  int(mtuNE.Value()),
		}
	}

	onConnect := func() {
		c := currentCfg()
		if err := SaveConfig(c); err != nil {
			log.Println("保存配置失败:", err)
		}
		tun.Connect(c.ToCore())
	}
	onDisconnect := func() {
		tun.Disconnect()
	}
	// 托盘退出:置退出标记后走窗口 Closing 事件统一处理
	onExit := func() {
		tray.quitting = true
		_ = mw.Close()
	}

	if err := (MainWindow{
		AssignTo: &mw,
		Title:    "Open Tunnel 客户端",
		Font:     Font{Family: "Microsoft YaHei UI", PointSize: 10},
		MinSize:  Size{Width: 440, Height: 560},
		Size:     Size{Width: 480, Height: 640},
		Layout:   VBox{Margins: Margins{Left: 12, Top: 12, Right: 12, Bottom: 12}, Spacing: 12},
		Children: []Widget{
			GroupBox{
				Title:  "服务器",
				Layout: Grid{Columns: 2, Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 12}, Spacing: 8},
				Children: []Widget{
					Label{Text: "地址:"},
					LineEdit{AssignTo: &addrLE, CueBanner: "127.0.0.1:9000"},
					Label{Text: "账户:"},
					LineEdit{AssignTo: &accountLE, CueBanner: "请输入账户"},
					Label{Text: "密码:"},
					LineEdit{AssignTo: &passwordLE, PasswordMode: true, CueBanner: "请输入密码"},
				},
			},
			GroupBox{
				Title:  "虚拟网卡",
				Layout: Grid{Columns: 2, Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 12}, Spacing: 8},
				Children: []Widget{
					Label{Text: "网卡名称:"},
					LineEdit{AssignTo: &ifaceNameLE, CueBanner: "tun0"},
					Label{Text: "IPv4 地址:"},
					LineEdit{AssignTo: &ifaceAddrLE, CueBanner: "192.168.10.1/24"},
					Label{Text: "MTU:"},
					NumberEdit{AssignTo: &mtuNE, Decimals: 0, MinValue: 576, MaxValue: 65535},
				},
			},
			GroupBox{
				Title:  "高级",
				Layout: Grid{Columns: 2, Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 12}, Spacing: 8},
				Children: []Widget{
					Label{Text: "心跳间隔(秒):"},
					NumberEdit{AssignTo: &keepaliveNE, Decimals: 0, MinValue: 1, MaxValue: 3600},
					Label{Text: "超时时间(秒):"},
					NumberEdit{AssignTo: &timeoutNE, Decimals: 0, MinValue: 1, MaxValue: 3600},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 4, Top: 4, Right: 4, Bottom: 4}, Spacing: 12},
				Children: []Widget{
					PushButton{AssignTo: &connectBtn, Text: "连接", OnClicked: onConnect},
					PushButton{AssignTo: &disconnectBtn, Text: "断开", Enabled: false, OnClicked: onDisconnect},
					HSpacer{},
					Label{AssignTo: &statusLbl, Text: "已断开", TextColor: walk.RGB(192, 0, 0)},
				},
			},
			TextEdit{
				AssignTo: &logTE, ReadOnly: true, VScroll: true,
				MinSize: Size{Height: 220},
				Font:    Font{Family: "Consolas", PointSize: 9},
			},
		},
	}).Create(); err != nil {
		log.Fatal(err)
	}

	// 从持久化配置回填表单
	_ = addrLE.SetText(cfg.Addr)
	_ = accountLE.SetText(cfg.Account)
	_ = passwordLE.SetText(cfg.Password)
	_ = ifaceNameLE.SetText(cfg.InterfaceName)
	_ = ifaceAddrLE.SetText(cfg.InterfaceAddr)
	_ = mtuNE.SetValue(float64(cfg.InterfaceMTU))
	_ = keepaliveNE.SetValue(float64(cfg.KeepaliveSec))
	_ = timeoutNE.SetValue(float64(cfg.TimeoutSec))

	tun = NewTunnel(mw, statusLbl, connectBtn, disconnectBtn)

	// 日志截获:标记"创建网卡完成"时推进连接状态(core 不提供回调,以日志为信号)
	sink := NewLogSink(mw, logTE, func(text string) {
		if tun.State() == stateConnecting && containsMarker(text) {
			tun.MarkConnected()
		}
	})
	log.SetOutput(sink)

	tray, err := NewTray(mw, onExit)
	if err != nil {
		log.Fatal(err)
	}
	defer tray.Dispose()

	// declarative MainWindow 没有 OnClosing 字段,最小化到托盘必须用运行时 API
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if tray.quitting {
			// 真退出:若隧道仍在运行,等 Serve 收尾后再结束进程
			*canceled = !tun.Shutdown(func() {
				walk.App().Exit(0)
			})
			return
		}
		// 普通点 X:隐藏到托盘继续运行
		*canceled = true
		mw.Hide()
		tray.NotifyHidden()
	})

	mw.Run()
}
