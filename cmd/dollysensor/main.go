// Command dollysensor runs the complete Dolly Sensor service.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dollysensor/internal/api"
	"dollysensor/internal/config"
	"dollysensor/internal/sensor"
	"dollysensor/internal/version"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	check := flag.Bool("check", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	defaultConfig := flag.Bool("default-config", false, "print a starter configuration and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("dollysensor " + version.Version)
		return
	}
	if *defaultConfig {
		cfg := config.Default()
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "encode default config:", err)
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, warnings, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration rejected", "error", err.Error())
		os.Exit(1)
	}
	for _, warning := range warnings {
		logger.Warn("configuration warning", "warning", warning)
	}
	if *check {
		fmt.Println("configuration is valid")
		return
	}

	service, err := sensor.New(cfg, warnings, logger)
	if err != nil {
		logger.Error("sensor initialization failed", "error", err.Error())
		os.Exit(1)
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runCtx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	if err := service.Start(runCtx); err != nil {
		logger.Error("sensor failed to start", "error", err.Error())
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = service.Close(closeCtx)
		closeCancel()
		os.Exit(1)
	}
	logger.Info("Dolly Sensor started", "version", version.Version, "simulation", !cfg.BGP.Enabled)

	dashboard := api.New(service, logger)
	apiErr := make(chan error, 1)
	go func() {
		apiErr <- dashboard.Run(runCtx)
	}()

	exitCode := 0
	select {
	case <-signalCtx.Done():
		logger.Info("shutdown requested")
	case err := <-apiErr:
		if err != nil {
			logger.Error("dashboard server stopped", "error", err.Error())
			exitCode = 1
		}
		cancel()
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := service.Close(shutdownCtx); err != nil {
		logger.Error("sensor shutdown warning", "error", err.Error())
		exitCode = 1
	}

	select {
	case err := <-apiErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("dashboard shutdown warning", "error", err.Error())
			exitCode = 1
		}
	case <-time.After(8 * time.Second):
		logger.Warn("dashboard shutdown timed out")
	}
	logger.Info("Dolly Sensor stopped")
	os.Exit(exitCode)
}
