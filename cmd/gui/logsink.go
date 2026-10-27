//go:build windows

package main

import (
	"strings"
	"time"

	"github.com/lxn/walk"
)

// connectedMarker 是 core.Client 连接成功(网卡创建完成)的日志标记。
// core 不提供状态回调,以日志文本为信号推进 UI 状态;标记失效时
// 状态会停留在"连接中…",断开/出错仍能正常流转,只是降级。
const connectedMarker = "创建网卡完成"

func containsMarker(text string) bool {
	return strings.Contains(text, connectedMarker)
}

// LogSink 实现 io.Writer,截获标准 log 输出显示到界面的日志窗口。
//
// Write 可能被 core 的任意 goroutine 高频调用(每个数据包都可能打日志),
// 因此先投递到带缓冲 channel(满则丢弃),由 pump 协程按 200ms 批量
// 合并后经 Synchronize 投递到 UI 线程,避免刷爆消息队列。
type LogSink struct {
	ch     chan string
	mw     *walk.MainWindow
	te     *walk.TextEdit
	onLine func(text string) // 每批日志的回调,在 pump 协程调用
}

func NewLogSink(mw *walk.MainWindow, te *walk.TextEdit, onLine func(string)) *LogSink {
	s := &LogSink{
		ch:     make(chan string, 1024),
		mw:     mw,
		te:     te,
		onLine: onLine,
	}
	go s.pump()
	return s
}

// Write 非阻塞写入:队列满时丢弃日志,绝不阻塞调用方。
func (s *LogSink) Write(p []byte) (int, error) {
	select {
	case s.ch <- string(p):
	default:
	}
	return len(p), nil
}

func (s *LogSink) pump() {
	var buf strings.Builder
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		text := buf.String()
		buf.Reset()
		s.mw.Synchronize(func() {
			s.te.AppendText(text)
			s.te.ScrollToCaret()
		})
		if s.onLine != nil {
			s.onLine(text)
		}
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case line := <-s.ch:
			buf.WriteString(line)
		case <-ticker.C:
			flush()
		}
	}
}
