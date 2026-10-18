/*
Copyright © 2026
*/
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"open-tunnel/internal/control"
	"open-tunnel/internal/core"
)

var (
	serverAddr            string
	serverAuthMemory      bool
	serverAuthMemoryFile  string
	checkHealthInterval   time.Duration
	checkHealthTimeout    time.Duration
	serverControlAddr     string
	serverControlUsername string
	serverControlPassword string
	serverControlCert     string
	serverControlKey      string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the tunnel server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := core.SrvCfg{
			Addr:                serverAddr,
			CheckHealthInterval: checkHealthInterval,
			CheckHealthTimeout:  checkHealthTimeout,
		}
		if serverAuthMemory {
			cfg.UserStore = core.NewUserStoreMemory()
			if len(serverAuthMemoryFile) > 0 {
				us, err := core.NewUserStoreMemoryWithFile(serverAuthMemoryFile)
				if err != nil {
					return err
				}
				cfg.UserStore = us
			}
		}
		if serverControlAddr != "" {
			if serverControlUsername == "" || serverControlPassword == "" {
				return fmt.Errorf("--control-addr requires --control-username and --control-password")
			}
		} else if serverControlUsername != "" || serverControlPassword != "" || serverControlCert != "" || serverControlKey != "" {
			return fmt.Errorf("--control-username/--control-password/--control-cert/--control-key require --control-addr")
		}
		srv := core.NewServer(cfg)

		var ctl *control.Control
		if serverControlAddr != "" {
			var err error
			ctl, err = control.New(control.Cfg{
				Addr:     serverControlAddr,
				Username: serverControlUsername,
				Password: serverControlPassword,
				Server:   srv,
				CertFile: serverControlCert,
				KeyFile:  serverControlKey,
			})
			if err != nil {
				return err
			}
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// 控制面同步监听，端口被占用等错误立即返回
		var ctlLn net.Listener
		if ctl != nil {
			var err error
			ctlLn, err = ctl.Listen()
			if err != nil {
				return err
			}
			defer func() {
				if err := ctlLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Println(err)
				}
			}()
			log.Printf("control plane listening on %s://%s", map[bool]string{true: "https", false: "http"}[ctl.TLS()], serverControlAddr)
		}

		go func() {
			<-ctx.Done()
			srv.Stop()
		}()

		ctlErr := make(chan error, 1)
		if ctl != nil {
			go func() {
				ctlErr <- ctl.Serve(ctlLn, ctx)
			}()
		}

		log.Printf("server listening on %s", serverAddr)
		srvErr := make(chan error, 1)
		go func() {
			srvErr <- srv.Serve(ctx)
		}()
		// 数据面和控制面任一异常退出都终止进程；正常 ctx 取消返回 nil
		select {
		case err := <-srvErr:
			return err
		case err := <-ctlErr:
			srv.Stop()
			if err == nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return fmt.Errorf("control plane: %w", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVar(&serverAddr, "addr", "0.0.0.0:9000", "UDP listen address")
	serverCmd.Flags().BoolVar(&serverAuthMemory, "auth-memory", false, "require account authentication after connection, clients that fail cannot join the server node (accounts kept in memory)")
	serverCmd.Flags().StringVar(&serverAuthMemoryFile, "auth-memory-file", "", "account data source file, one account:password per line; optional, accounts may also be provided by other means")
	serverCmd.Flags().DurationVar(&checkHealthInterval, "health-interval", time.Minute, "health check interval")
	serverCmd.Flags().DurationVar(&checkHealthTimeout, "health-timeout", 2*time.Minute, "session timeout without keepalive")
	serverCmd.Flags().StringVar(&serverControlAddr, "control-addr", "", "HTTP(S) listen address of the control plane, e.g. 127.0.0.1:8080; setting it enables the control plane")
	serverCmd.Flags().StringVar(&serverControlUsername, "control-username", "", "basic auth username for the control plane")
	serverCmd.Flags().StringVar(&serverControlPassword, "control-password", "", "basic auth password for the control plane")
	serverCmd.Flags().StringVar(&serverControlCert, "control-cert", "", "TLS certificate PEM file for the control plane, enables HTTPS when paired with --control-key")
	serverCmd.Flags().StringVar(&serverControlKey, "control-key", "", "TLS private key PEM file for the control plane")
}
