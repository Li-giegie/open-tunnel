/*
Copyright © 2026
*/
package cmd

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"open-tunnel/internal"
)

var (
	clientAddr     string
	clientUsername string
	clientPassword string
	keepalive      time.Duration
	timeout        time.Duration
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start the tunnel client",
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetFlags(log.Llongfile | log.Lshortfile | log.LstdFlags)
		cli := internal.NewClient(internal.CliCfg{
			Addr:      clientAddr,
			Username:  clientUsername,
			Password:  clientPassword,
			Keepalive: keepalive,
			Timeout:   timeout,
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
	clientCmd.Flags().StringVar(&clientUsername, "username", "", "auth username")
	clientCmd.Flags().StringVar(&clientPassword, "password", "", "auth password")
	clientCmd.Flags().DurationVar(&keepalive, "keepalive", 15*time.Second, "keepalive interval")
	clientCmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "disconnect timeout without pong")

	clientCmd.Flags().Func("ip", "", func(s string) error {
		go func() {
			for _, cmd := range []string{"ip addr add " + s + " dev tun0", "ip link set tun0 up"} {
				for {
					time.Sleep(2 * time.Second)
					out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
					if err != nil {
						log.Println(err, string(out), cmd)
						continue
					}
					break
				}
			}
		}()
		return nil
	})
}
