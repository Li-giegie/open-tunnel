//go:build windows

package main

import (
	"context"
	"errors"
	"time"

	"github.com/lxn/walk"

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

// Tunnel 管理 core.Client 的生命周期(连接/断开/退出时序)。
// t.state 只在 UI 线程读写:Connect/Disconnect 由按钮回调(UI 线程)调用,
// Serve goroutine 与 MarkConnected 经 Synchronize 回到 UI 线程再改状态。
// t.cli/t.cancel/t.done 同样只在 UI 线程赋值,各协程捕获局部引用使用。
type Tunnel struct {
	mw            *walk.MainWindow
	statusLbl     *walk.Label
	connectBtn    *walk.PushButton
	disconnectBtn *walk.PushButton

	cli    *core.Client
	cancel context.CancelFunc
	done   chan struct{} // Serve 返回后关闭
	state  state
}

func NewTunnel(mw *walk.MainWindow, statusLbl *walk.Label, connectBtn, disconnectBtn *walk.PushButton) *Tunnel {
	return &Tunnel{
		mw:            mw,
		statusLbl:     statusLbl,
		connectBtn:    connectBtn,
		disconnectBtn: disconnectBtn,
		state:         stateDisconnected,
	}
}

func (t *Tunnel) State() state { return t.state }

// setState 更新状态并同步刷新控件(仅允许在 UI 线程调用)。
func (t *Tunnel) setState(s state) {
	t.state = s
	_ = t.statusLbl.SetText(s.String())
	t.statusLbl.SetTextColor(s.color())
	t.connectBtn.SetEnabled(s == stateDisconnected)
	t.disconnectBtn.SetEnabled(s == stateConnecting || s == stateConnected)
}

// Connect 发起连接。仅允许在 UI 线程调用,且当前必须处于已断开状态。
// 每次连接都新建 Client:Serve 可重入,新建实例可避免 sessionId 等内部状态残留。
func (t *Tunnel) Connect(cfg core.CliCfg) {
	if t.state != stateDisconnected {
		return
	}
	t.cli = core.NewClient(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.done = make(chan struct{})
	t.setState(stateConnecting)

	cli, done := t.cli, t.done
	go func() {
		err := cli.Serve(ctx)
		// 先把状态刷新入队、再关闭 done,保证 Shutdown 的退出回调排在状态刷新之后
		t.mw.Synchronize(func() {
			t.setState(stateDisconnected)
			if err != nil && !errors.Is(err, context.Canceled) {
				walk.MsgBox(t.mw, "连接已断开", err.Error(), walk.MsgBoxIconError)
			}
		})
		close(done)
	}()
}

// MarkConnected 由日志标记触发,把"连接中…"推进为"已连接"。
func (t *Tunnel) MarkConnected() {
	t.mw.Synchronize(func() {
		if t.state == stateConnecting {
			t.setState(stateConnected)
		}
	})
}

// Disconnect 断开连接。仅允许在 UI 线程调用。
//
// 注意:认证阶段(最长 1 分钟)core 内部的 cancel 尚未赋值,
// 此时 cli.Stop() 是 no-op,用 watchdog 周期性重调(幂等)兜底。
func (t *Tunnel) Disconnect() {
	if t.state == stateDisconnected {
		return
	}
	t.setState(stateStopping)
	t.cancel()
	cli, done := t.cli, t.done
	cli.Stop()
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(500 * time.Millisecond):
				cli.Stop()
			}
		}
	}()
}

// Shutdown 请求退出。返回 true 表示没有运行中的连接,调用方可直接退出;
// 返回 false 表示正在等待 Serve 收尾,exit 会在收尾完成后于 UI 线程被调用。
func (t *Tunnel) Shutdown(exit func()) bool {
	if t.state == stateDisconnected {
		return true
	}
	t.Disconnect()
	done := t.done
	go func() {
		<-done
		t.mw.Synchronize(exit)
	}()
	return false
}
