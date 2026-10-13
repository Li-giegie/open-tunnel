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

	"open-tunnel/internal"
)

var (
	serverAddr          string
	serverUsers         string
	checkHealthInterval time.Duration
	checkHealthTimeout  time.Duration
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the tunnel server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := internal.SrvCfg{
			Addr:                serverAddr,
			CheckHealthInterval: checkHealthInterval,
			CheckHealthTimeout:  checkHealthTimeout,
		}
		if serverUsers != "" {
			cfg.Validator = internal.NewMemoryValidator(internal.ParseUserPasswords(serverUsers))
		}
		srv := internal.NewServer(cfg)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		go func() {
			<-ctx.Done()
			srv.Stop()
		}()

		log.Printf("server listening on %s", serverAddr)
		return srv.Serve(ctx)
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVar(&serverAddr, "addr", "0.0.0.0:9000", "UDP listen address")
	serverCmd.Flags().StringVar(&serverUsers, "users", "", "username:password pairs, comma separated (e.g. alice:secret,bob:123456)")
	serverCmd.Flags().DurationVar(&checkHealthInterval, "health-interval", time.Minute, "health check interval")
	serverCmd.Flags().DurationVar(&checkHealthTimeout, "health-timeout", 2*time.Minute, "session timeout without keepalive")
}
