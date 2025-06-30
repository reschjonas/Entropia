package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"

	"entropia/internal/app"
	"entropia/internal/config"
	"entropia/internal/logger"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.4-e2e"

	rootCmd = &cobra.Command{
		Use:     "entropia",
		Short:   "A GUI-based post-quantum end-to-end encrypted chat application.",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runApp()
		},
	}

	// CLI global flags
	logLevelFlag string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "", "Set log level (debug, info, warn, error). Overrides $ENTROPIA_LOG_LEVEL")

	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if logLevelFlag != "" {
			// apply user-provided level
			lvl := logger.ParseLevel(logLevelFlag)
			logger.SetLevel(lvl)
			logger.L().Info("Log level set via CLI flag", "level", logLevelFlag)
		}
	}
}

func main() {
	// silence all logging to keep chat interface clean
	log.SetOutput(io.Discard)
	log.SetFlags(0)

	// Webview must run on the main OS thread
	runtime.LockOSThread()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runApp() error {
	cfg := config.DefaultConfig()
	ctx := context.Background()

	entApp, err := app.NewEntropia(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize Entropia: %w", err)
	}
	defer entApp.Close()

	// The app lifecycle is now handled by the GUI
	return entApp.StartGUILifecycle(ctx)
}
