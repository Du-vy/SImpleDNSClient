//go:build windows
// +build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	ErrServiceNotFound = errors.New("service is not installed")
)

// StatusInfo represents the current state of a Windows Service.
type StatusInfo struct {
	Installed   bool
	State       string
	ProcessID   uint32
	CanStop     bool
	ExitCode    uint32
	ConfigPath  string
	Description string
}

// Install registers SimpleDNS as an automatically starting Windows Service.
func Install(cfg config.ServiceConfig, configFilePath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	absExePath, err := filepath.Abs(exePath)
	if err != nil {
		absExePath = exePath
	}

	absConfigPath, err := filepath.Abs(configFilePath)
	if err != nil {
		absConfigPath = configFilePath
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w (administrator privileges required)", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(cfg.Name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service '%s' is already installed; uninstall it first", cfg.Name)
	}

	serviceMgrConfig := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic, // Auto-start on boot
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  cfg.DisplayName,
		Description:  cfg.Description,
		Dependencies: []string{"Tcpip", "Nsi"},
	}

	s, err = m.CreateService(cfg.Name, absExePath, serviceMgrConfig, "run", "-c", absConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create service '%s': %w", cfg.Name, err)
	}
	defer s.Close()

	// Configure recovery action: restart service on failure
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.NoAction, Delay: 0},
	}
	_ = s.SetRecoveryActions(recoveryActions, 86400) // Reset fail count after 24h

	return nil
}

// Uninstall stops and removes the Windows Service.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", name, err)
	}
	defer s.Close()

	// Stop service first if running
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		_, _ = s.Control(svc.Stop)
		// Wait up to 10 seconds for service to stop
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err := s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("failed to delete service '%s': %w", name, err)
	}

	return nil
}

// Start launches the installed Windows Service.
func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", name, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("failed to start service '%s': %w", name, err)
	}

	return nil
}

// Stop sends a stop command to the running Windows Service.
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service '%s' is not installed: %w", name, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service '%s': %w", name, err)
	}

	// Wait up to 10 seconds for service to reach Stopped state
	deadline := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			break
		}
	}

	return nil
}

// Status queries the status of the Windows Service.
func Status(name string) (StatusInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return StatusInfo{Installed: false}, fmt.Errorf("failed to connect to Service Control Manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return StatusInfo{Installed: false}, nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return StatusInfo{Installed: true, State: "unknown"}, fmt.Errorf("failed to query service status: %w", err)
	}

	stateStr := "unknown"
	switch status.State {
	case svc.Stopped:
		stateStr = "stopped"
	case svc.StartPending:
		stateStr = "start_pending"
	case svc.StopPending:
		stateStr = "stop_pending"
	case svc.Running:
		stateStr = "running"
	case svc.ContinuePending:
		stateStr = "continue_pending"
	case svc.PausePending:
		stateStr = "pause_pending"
	case svc.Paused:
		stateStr = "paused"
	}

	canStop := (status.Accepts & svc.AcceptStop) != 0
	processID := status.ProcessId

	cfg, _ := s.Config()

	return StatusInfo{
		Installed:   true,
		State:       stateStr,
		ProcessID:   processID,
		CanStop:     canStop,
		ExitCode:    status.Win32ExitCode,
		Description: cfg.Description,
	}, nil
}
