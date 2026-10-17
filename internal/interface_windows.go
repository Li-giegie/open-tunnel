// Package internal 是 golang.zx2c4.com/wintun 底层 API 的易用封装。
//
// 对外提供:
//   - Interface 接口: Name() + io.ReadWriteCloser, 阻塞式读写 L3(IPv4/IPv6)数据包
//   - 网卡配置: IP 地址、路由、MTU(经 netsh)
//   - LUID、关闭清理
//
// 使用要求:
//   - 以管理员权限运行(创建/删除网卡、netsh 都需要)
//   - wintun.dll 放在 exe 同目录或 System32 下
package internal

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const (
	// DefaultRingCapacity 收发环形缓冲区默认大小(4 MiB,须为 2 的幂)。
	DefaultRingCapacity = 0x800000
	// DefaultMTU 默认 MTU(与 WireGuard 一致,留余量给封装开销)。
	DefaultMTU = 1450
	// PacketSizeMax 单个 IP 包最大长度。
	PacketSizeMax = wintun.PacketSizeMax
)

// ErrClosed 设备已关闭(含读阻塞中被 Close 唤醒的情形)。
var ErrClosed = errors.New("tunx: device closed")

// 保证 Device 满足 Interface。
var _ Interface = (*Device)(nil)

// Device 一个 Wintun 虚拟网卡 + 收发会话。
// Read/Write 并发安全。
type Device struct {
	name      string
	adapter   *wintun.Adapter
	session   wintun.Session
	readEvent windows.Handle
	closed    chan struct{}
	closeOnce sync.Once
	guid      *windows.GUID
}

func CreateInterface(name string) (Interface, error) {
	return Open(name, 0)
}

// Open 创建(同名已存在则复用)Wintun 网卡并启动收发会话。name 设备名称 ringCapacity 环形缓冲区大小
func Open(name string, ringCapacity uint32) (*Device, error) {
	if ringCapacity == 0 {
		ringCapacity = DefaultRingCapacity
	}
	var guid *windows.GUID
	adapter, err := wintun.CreateAdapter(name, "Wintun", guid)
	if err != nil {
		adapter, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, fmt.Errorf("tunx: create adapter %q: %w", name, err)
		}
	}
	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("tunx: start session: %w", err)
	}
	return &Device{
		name:      name,
		adapter:   adapter,
		session:   session,
		readEvent: session.ReadWaitEvent(),
		closed:    make(chan struct{}),
		guid:      guid,
	}, nil
}

// Read 阻塞读取一个 L3 数据包到 p,返回包长。
// p 应不小于 PacketSizeMax,否则超长包会被截断(超出部分丢弃)。
func (d *Device) Read(p []byte) (int, error) {
	for {
		pkt, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(p, pkt)
			d.session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		if err := d.waitRead(err); err != nil {
			return 0, err
		}
	}
}

// Write 写入一个 L3 数据包。
// 环形缓冲区满时返回 ERROR_BUFFER_OVERFLOW,调用方可退避重试。
func (d *Device) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > PacketSizeMax {
		return 0, fmt.Errorf("tunx: packet too large: %d", len(p))
	}
	select {
	case <-d.closed:
		return 0, ErrClosed
	default:
	}
	buf, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		if err == windows.ERROR_HANDLE_EOF {
			return 0, ErrClosed
		}
		return 0, err
	}
	copy(buf, p)
	d.session.SendPacket(buf)
	return len(p), nil
}

// Name 返回网卡显示名。
func (d *Device) Name() string { return d.name }

// LUID 返回网卡 LUID,可用于 windows API 层面的接口操作。
func (d *Device) LUID() uint64 { return d.adapter.LUID() }

// Close 结束会话并释放网卡;若网卡是本次 Open 创建的,会被删除。
// 会唤醒所有阻塞中的 Read。
func (d *Device) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.closed)
		d.session.End()
		err = d.adapter.Close()
	})
	return err
}

func (d *Device) GUID() *windows.GUID { return d.guid }

// waitRead 处理无数据可读的情形:等待读事件后被唤醒返回 nil(应重试);
// 其余错误原样返回,会话结束映射为 ErrClosed。
func (d *Device) waitRead(err error) error {
	if err != windows.ERROR_NO_MORE_ITEMS {
		if err == windows.ERROR_HANDLE_EOF {
			return ErrClosed
		}
		return err
	}
	if _, werr := windows.WaitForSingleObject(d.readEvent, windows.INFINITE); werr != nil {
		return werr
	}
	select {
	case <-d.closed:
		return ErrClosed
	default:
	}
	return nil
}

// SetIPv4Address 配置网卡静态 IPv4 地址(需管理员权限)。
// 例: dev.SetIPv4Address(net.IP{192,168,200,1}, net.CIDRMask(24,32))
func SetIPv4Address(name string, ip net.IP, mask net.IPMask) error {
	if ip.To4() == nil {
		return fmt.Errorf("ip invalid: %s ipv6 address is not supported", ip.String())
	}
	if _, bits := mask.Size(); bits == 0 || bits == 128 {
		return fmt.Errorf("mask invalid: %s ipv6 masks are not supported", mask.String())
	}
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", quote(name)),
		"source=static",
		fmt.Sprintf("addr=%s", ip),
		fmt.Sprintf("mask=%s", net.IPv4(mask[0], mask[1], mask[2], mask[3])),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set address failed: cmd='%s' %v: %s", cmd.String(), err, string(out))
	}
	return nil
}

// SetMTU 设置网卡 MTU(IPv4/IPv6 同时设置,需管理员权限),
// 并更新 MTU() 的返回值。
// netsh interface ipv4 set subinterface "以太网 9" mtu=1492 store=persistent
func SetMTU(name string, mtu int) error {
	if mtu < 576 || mtu > 65535 {
		return fmt.Errorf("invalid MTU: %d", mtu)
	}
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", quote(name), "mtu="+strconv.Itoa(mtu), "store=persistent")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set interface failed: cmd='%s' %v: %s", cmd.String(), err, string(out))
	}
	return nil
}

func quote(s string) string {
	if !strings.HasPrefix(s, "\"") {
		s = "\"" + s
	}
	if !strings.HasSuffix(s, "\"") {
		s = s + "\""
	}
	return s
}
