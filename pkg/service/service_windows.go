//go:build windows
// +build windows

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/engine"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"golang.org/x/sys/windows/svc"
)

// WindowsService implements the svc.Handler interface for Windows Service Control Manager.
type WindowsService struct {
	cfg    *config.Config
	engine *engine.Engine
}

// NewWindowsService creates a new Windows service handler.
func NewWindowsService(cfg *config.Config) *WindowsService {
	return &WindowsService{
		cfg: cfg,
	}
}

// Execute is called by the Windows Service Control Manager when the service starts.
func (ws *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Initialize the exact same core engine as console mode
	eng, err := engine.New(ws.cfg)
	if err != nil {
		logger.L().Error("failed to initialize SimpleDNS engine in service mode", "error", err)
		return false, 1
	}
	ws.engine = eng

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := ws.engine.Start(ctx); err != nil {
		logger.L().Error("failed to start SimpleDNS engine in service mode", "error", err)
		return false, 2
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	logger.L().Info("SimpleDNS Windows Service is running")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing short wait
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus

			case svc.Stop, svc.Shutdown:
				logger.L().Info("Windows Service received stop/shutdown command", "command", c.Cmd)
				changes <- svc.Status{State: svc.StopPending}

				cancel()
				if err := ws.engine.Stop(); err != nil {
					logger.L().Warn("error while stopping engine during service shutdown", "error", err)
				}

				changes <- svc.Status{State: svc.Stopped}
				return false, 0

			default:
				logger.L().Warn("unexpected service control request", "cmd", c.Cmd)
			}
		}
	}
}

// RunService runs the application within the Windows Service environment.
func RunService(name string, cfg *config.Config) error {
	ws := NewWindowsService(cfg)
	err := svc.Run(name, ws)
	if err != nil {
		return fmt.Errorf("failed to run Windows service '%s': %w", name, err)
	}
	return nil
}

// IsWindowsService checks if the current process is running as a Windows Service.
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}
