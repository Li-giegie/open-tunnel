/*
Copyright © 2026
*/
package cmd

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"open-tunnel/internal/core"
)

var (
	clientAddr     string
	clientAccount  string
	clientPassword string
	keepalive      time.Duration
	timeout        time.Duration
	interfaceName  string
	interfaceAddr  string
	interfaceMTU   int
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the tunnel client",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetFlags(log.Llongfile | log.Lshortfile | log.LstdFlags)
		cli := core.NewClient(core.CliCfg{
			Addr:          clientAddr,
			Account:       clientAccount,
			Password:      clientPassword,
			Keepalive:     keepalive,
			Timeout:       timeout,
			InterfaceName: interfaceName,
			InterfaceAddr: interfaceAddr,
			InterfaceMTU:  interfaceMTU,
		})

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		go func() {
			<-ctx.Done()
			cli.Stop()
		}()

		log.Printf("client connecting to %s", clientAddr)
		return cli.Serve(ctx)
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)

	clientCmd.Flags().StringVar(&clientAddr, "addr", "127.0.0.1:9000", "server UDP address")
	clientCmd.Flags().StringVar(&clientAccount, "account", "", "auth account")
	clientCmd.Flags().StringVar(&clientPassword, "password", "", "auth password")
	clientCmd.Flags().DurationVar(&keepalive, "keepalive", 15*time.Second, "keepalive interval")
	clientCmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "disconnect timeout without pong")
	clientCmd.Flags().StringVar(&interfaceName, "interface-name", "tun0", "interface name")
	clientCmd.Flags().StringVar(&interfaceAddr, "interface-addr", "192.168.10.1/24", "interface address：192.168.10.1/24")
	clientCmd.Flags().IntVar(&interfaceMTU, "interface-mtu", 1450, "interface MTU")
}
