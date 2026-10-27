//go:build windows

package main

import (
	"github.com/lxn/walk"
)

// Tray 管理系统托盘图标:左键单击恢复主窗口,右键菜单提供显示/退出。
// 使用系统预置图标,无需自定义 .ico 资源。
type Tray struct {
	ni       *walk.NotifyIcon
	quitting bool  // 用户已请求退出(Closing 处理器读取)
	notified bool  // 是否已提示过"已最小化到托盘"
}

func NewTray(mw *walk.MainWindow, onExit func()) (*Tray, error) {
	ni, err := walk.NewNotifyIcon(mw)
	if err != nil {
		return nil, err
	}
	t := &Tray{ni: ni}
	if err = ni.SetIcon(walk.IconApplication()); err != nil {
		ni.Dispose()
		return nil, err
	}
	_ = ni.SetToolTip("Open Tunnel 客户端")

	// 左键单击恢复主窗口
	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			mw.Show()
			_ = mw.Activate()
		}
	})

	show := walk.NewAction()
	_ = show.SetText("显示主窗口")
	show.Triggered().Attach(func() {
		mw.Show()
		_ = mw.Activate()
	})
	exit := walk.NewAction()
	_ = exit.SetText("退出")
	exit.Triggered().Attach(onExit)

	menu := ni.ContextMenu()
	menu.Actions().Add(show)
	menu.Actions().Add(exit)
	_ = ni.SetVisible(true)
	return t, nil
}

// NotifyHidden 首次隐藏到托盘时气泡提示一次。
func (t *Tray) NotifyHidden() {
	if t.notified {
		return
	}
	t.notified = true
	_ = t.ni.ShowInfo("Open Tunnel", "程序已最小化到托盘,单击托盘图标可恢复窗口")
}

// Dispose 释放托盘图标资源。
func (t *Tray) Dispose() {
	t.ni.Dispose()
}
