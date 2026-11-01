//go:build windows

// Package main 提供 open-tunnel 客户端的 Windows 图形界面(基于 lxn/walk)。
//
// 构建(需先生成 rsrc_windows_amd64.syso,见 gui.exe.manifest 说明):
//
//	go build -ldflags="-H windowsgui" -o bin/gui.exe ./internal/gui/client
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"

	"open-tunnel/internal/core"
)

type state int

const (
	stateDisconnected state = iota
	stateConnecting
	stateConnected
	stateStopping
)

func (s state) String() string {
	switch s {
	case stateConnecting:
		return "连接中…"
	case stateConnected:
		return "已连接"
	case stateStopping:
		return "断开中…"
	default:
		return "已断开"
	}
}

// color 返回状态标签的前景色。
func (s state) color() walk.Color {
	switch s {
	case stateConnected:
		return walk.RGB(0, 138, 0) // 绿
	case stateConnecting, stateStopping:
		return walk.RGB(204, 116, 0) // 橙
	default:
		return walk.RGB(192, 0, 0) // 红
	}
}

func main() {
	cfg := LoadConfig()
	log.SetFlags(log.LstdFlags)

	var mw *walk.MainWindow

	var addrLE, accountLE, passwordLE, ifaceNameLE, ifaceAddrLE *walk.LineEdit
	var mtuNE, authTimeoutNE, keepaliveNE, timeoutNE *walk.NumberEdit
	var connectBtn, disconnectBtn *walk.PushButton
	var statusLbl *walk.Label
	var logTE *walk.TextEdit

	// 连接状态与生命周期。connState 只在 UI 线程读写:
	// connect/disconnect 由按钮回调(UI 线程)调用,日志标记回调经 LogSink 的
	// Synchronize 回到 UI 线程;cli/cancel/done 同样只在 UI 线程赋值,
	// 各协程捕获局部副本使用。
	var (
		connState = stateDisconnected
		cli       *core.Client
		cancel    context.CancelFunc
		done      chan struct{} // Serve 返回后关闭
	)

	currentCfg := func() Cfg {
		return Cfg{
			Addr:           addrLE.Text(),
			Account:        accountLE.Text(),
			Password:       passwordLE.Text(),
			KeepaliveSec:   int(keepaliveNE.Value()),
			TimeoutSec:     int(timeoutNE.Value()),
			AuthTimeoutSec: int(authTimeoutNE.Value()),
			InterfaceName:  ifaceNameLE.Text(),
			InterfaceAddr:  ifaceAddrLE.Text(),
			InterfaceMTU:   int(mtuNE.Value()),
		}
	}

	// setState 更新状态并同步刷新控件(仅允许在 UI 线程调用)。
	setState := func(s state) {
		connState = s
		_ = statusLbl.SetText(s.String())
		statusLbl.SetTextColor(s.color())
		connectBtn.SetEnabled(s == stateDisconnected)
		disconnectBtn.SetEnabled(s == stateConnecting || s == stateConnected)
	}

	// connect 发起连接。仅允许在 UI 线程调用,且当前必须处于已断开状态。
	// 每次连接都新建 Client:Serve 可重入,新建实例可避免 sessionId 等内部状态残留。
	connect := func(cfg core.CliCfg) {
		if connState != stateDisconnected {
			return
		}
		cli = core.NewClient(cfg)
		var ctx context.Context
		ctx, cancel = context.WithCancel(context.Background())
		done = make(chan struct{})
		setState(stateConnecting)

		c, d := cli, done
		go func() {
			err := c.Serve(ctx)
			// 先把状态刷新入队、再关闭 done,保证退出的回调排在状态刷新之后
			mw.Synchronize(func() {
				setState(stateDisconnected)
				if err != nil && !errors.Is(err, context.Canceled) {
					walk.MsgBox(mw, "连接已断开", err.Error(), walk.MsgBoxIconError)
				}
			})
			close(d)
		}()
	}

	// disconnect 断开连接。仅允许在 UI 线程调用。
	//
	// 注意:认证阶段(最长 1 分钟)core 内部的 cancel 尚未赋值,
	// 此时 cli.Stop() 是 no-op,用 watchdog 周期性重调(幂等)兜底。
	disconnect := func() {
		if connState == stateDisconnected {
			return
		}
		setState(stateStopping)
		cancel()
		c, d := cli, done
		c.Stop()
		go func() {
			for {
				select {
				case <-d:
					return
				case <-time.After(500 * time.Millisecond):
					c.Stop()
				}
			}
		}()
	}

	onConnect := func() {
		c := currentCfg()
		if err := SaveConfig(c); err != nil {
			log.Println("保存配置失败:", err)
		}
		connect(c.ToCore())
	}
	onDisconnect := func() {
		disconnect()
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
					Label{Text: "认证超时(秒):"},
					NumberEdit{AssignTo: &authTimeoutNE, Decimals: 0, MinValue: 1, MaxValue: 300},
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
	_ = authTimeoutNE.SetValue(float64(cfg.AuthTimeoutSec))
	_ = keepaliveNE.SetValue(float64(cfg.KeepaliveSec))
	_ = timeoutNE.SetValue(float64(cfg.TimeoutSec))

	// 日志截获:标记"创建网卡完成"时推进连接状态(core 不提供回调,以日志为信号)。
	// 回调经 LogSink 的 Synchronize 在 UI 线程执行,可直接读写 connState。
	sink := NewLogSink(mw, logTE, func(text string) {
		if connState == stateConnecting && containsMarker(text) {
			setState(stateConnected)
		}
	})
	log.SetOutput(sink)

	var tray *Tray
	// 托盘退出:置退出标记后走窗口 Closing 事件统一处理
	onExit := func() {
		tray.quitting = true
		_ = mw.Close()
	}
	tray, err := NewTray(mw, onExit)
	if err != nil {
		log.Fatal(err)
	}
	defer tray.Dispose()

	// declarative MainWindow 没有 OnClosing 字段,最小化到托盘必须用运行时 API
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if tray.quitting {
			// 真退出:没有运行中的连接则直接关闭,Run 返回后走 tray.Dispose;
			// 否则等 Serve 收尾再结束进程
			if connState == stateDisconnected {
				return
			}
			*canceled = true
			disconnect()
			d := done
			go func() {
				<-d
				mw.Synchronize(func() {
					walk.App().Exit(0)
				})
			}()
			return
		}
		// 普通点 X:隐藏到托盘继续运行
		*canceled = true
		mw.Hide()
		tray.NotifyHidden()
	})

	mw.Run()
}
