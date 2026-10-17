package internal

import (
	"fmt"
	"github.com/songgao/water"
	"net"
	"os/exec"
)

func CreateInterface(name string) (Interface, error) {
	iface, err := water.New(
		water.Config{
			DeviceType: water.TUN,
			PlatformSpecificParams: water.PlatformSpecificParams{
				Name: name,
			},
		},
	)
	if err != nil {
		return nil, err
	}
	return iface, nil
}

func SetIPv4Address(name string, ip net.IP, mask net.IPMask) error {
	if ip.To4() == nil {
		return fmt.Errorf("ip invalid: %s ipv6 address is not supported", ip.String())
	}
	ones, bits := mask.Size()
	if bits == 0 || bits == 128 {
		return fmt.Errorf("mask invalid: %s ipv6 masks are not supported", mask.String())
	}
	err := SetStatus(name, true)
	if err != nil {
		return err
	}

	cmd := exec.Command("bash", "-c", fmt.Sprintf("ip addr add %s/%d dev %s", ip, ones, name))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set address failed: cmd='%s' %v: %s", cmd.String(), err, string(out))
	}
	return nil
}

func SetMTU(name string, mtu int) error {
	err := SetStatus(name, true)
	if err != nil {
		return err
	}
	cmd := exec.Command("bash", "-c", fmt.Sprintf("ip link set mtu %d dev %s", mtu, name))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set address failed: cmd='%s' %v: %s", cmd.String(), err, string(out))
	}
	return nil
}

func SetStatus(name string, enable bool) error {
	status := "up"
	if !enable {
		status = "down"
	}
	cmd := exec.Command("bash", "-c", fmt.Sprintf("ip link set %s %s", name, status))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("set address failed: cmd='%s' %v: %s", cmd.String(), err, string(out))
	}
	return nil
}
