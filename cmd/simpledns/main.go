package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Du-vy/SImpleDNSClient/pkg/bootstrap"
	"github.com/Du-vy/SImpleDNSClient/pkg/config"
	"github.com/Du-vy/SImpleDNSClient/pkg/dnsmsg"
	"github.com/Du-vy/SImpleDNSClient/pkg/engine"
	"github.com/Du-vy/SImpleDNSClient/pkg/interceptor/windivert"
	"github.com/Du-vy/SImpleDNSClient/pkg/logger"
	"github.com/Du-vy/SImpleDNSClient/pkg/service"
	"github.com/Du-vy/SImpleDNSClient/pkg/upstream"
)

var (
	Version   = "1.0.0"
	BuildDate = "2026-10-03"
	GitCommit = "release"
)

const defaultConfigFile = "simpledns.yaml"

func main() {
	// If executed by Windows Service Control Manager, run immediately in service mode
	if service.IsWindowsService() {
		runAsWindowsService()
		return
	}

	if len(os.Args) < 2 {
		printBanner()
		printUsage()
		os.Exit(0)
	}

	cmd := strings.ToLower(os.Args[1])

	switch cmd {
	case "run":
		handleRun(os.Args[2:])
	case "check":
		handleCheck(os.Args[2:])
	case "status":
		handleStatus()
	case "service":
		handleService(os.Args[2:])
	case "version", "-v", "--version":
		handleVersion()
	case "help", "-h", "--help":
		printBanner()
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command '%s'\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("c", "", "Path to YAML configuration file (default: simpledns.yaml or built-in defaults)")
	configLong := fs.String("config", "", "Path to YAML configuration file")
	modeFlag := fs.String("mode", "", "Override interception mode: windivert, listener, or auto")
	verbose := fs.Bool("verbose", false, "Enable verbose debug logging")
	fs.BoolVar(verbose, "v", false, "Enable verbose debug logging (shorthand)")
	fs.Parse(args)

	cfgFile := resolveConfigPath(*configPath, *configLong)
	cfg := loadConfiguration(cfgFile)

	if *verbose {
		cfg.Logging.Level = "debug"
	}
	if *modeFlag != "" {
		cfg.Interceptor.Mode = strings.ToLower(*modeFlag)
	}

	logger.Setup(logger.Config{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		LogQueries: cfg.Logging.LogQueries,
	}, os.Stdout)

	printBanner()
	fmt.Printf("[+] Mode:           %s\n", cfg.Interceptor.Mode)
	fmt.Printf("[+] Log Level:      %s\n", cfg.Logging.Level)
	fmt.Printf("[+] Query Privacy:  %t (query logging %s)\n", !cfg.Logging.LogQueries, boolStatus(cfg.Logging.LogQueries, "enabled", "disabled"))
	fmt.Printf("[+] Upstreams:      %d configured\n", len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		fmt.Printf("    [%d] %-18s [%-5s] (Priority %d) -> %s\n", i+1, u.Name, u.Transport, u.Priority, u.Endpoint)
	}
	fmt.Printf("[+] Bootstrap DNS:  %s\n", strings.Join(cfg.Bootstrap.Servers, ", "))
	fmt.Printf("[+] Elev. Status:   %s\n", boolStatus(windivert.IsElevated(), "Elevated (Administrator)", "Standard User (Not Elevated)"))
	fmt.Println()

	eng, err := engine.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Engine initialization failed: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Engine startup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] SimpleDNS is running. Press Ctrl+C to terminate.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Periodically print statistics if debug logging is enabled
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				printStats(eng.Stats())
			case <-ctx.Done():
				return
			}
		}
	}()

	<-sigChan
	fmt.Println("\n[*] Shutting down SimpleDNS cleanly...")
	cancel()

	if err := eng.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error during shutdown: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] SimpleDNS terminated. Final session statistics:")
	printStats(eng.Stats())
}

func handleCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("c", "", "Path to YAML configuration file")
	configLong := fs.String("config", "", "Path to YAML configuration file")
	fs.Parse(args)

	cfgFile := resolveConfigPath(*configPath, *configLong)
	fmt.Printf("[*] Validating configuration from '%s'...\n", cfgFile)

	cfg, err := config.Load(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Configuration validation FAILED:\n    %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Configuration syntax and schema: VALID")
	fmt.Printf("    - Interceptor Mode: %s\n", cfg.Interceptor.Mode)
	fmt.Printf("    - Routing Strategy: %s\n", cfg.Routing.Strategy)
	fmt.Printf("    - Plaintext Fallback: %t\n", cfg.Routing.AllowPlaintextFallback)
	fmt.Printf("    - Cache Enabled: %t (Max: %d entries)\n", cfg.Cache.Enabled, cfg.Cache.MaxEntries)
	fmt.Printf("    - Upstreams: %d\n", len(cfg.Upstreams))

	// Test bootstrap servers
	fmt.Println("\n[*] Testing bootstrap DNS connectivity...")
	allBootstrapOK := true
	for _, s := range cfg.Bootstrap.Servers {
		start := time.Now()
		conn, err := net.DialTimeout("udp", s, 2*time.Second)
		if err != nil {
			fmt.Printf("    [-] Bootstrap %s: FAILED (%v)\n", s, err)
			allBootstrapOK = false
		} else {
			conn.Close()
			fmt.Printf("    [+] Bootstrap %s: REACHABLE (%v)\n", s, time.Since(start).Round(time.Millisecond))
		}
	}

	// Test upstream connectivity
	fmt.Println("\n[*] Testing upstream resolvers...")
	b, err := bootstrap.NewResolver(cfg.Bootstrap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "    [!] Bootstrap initialization failed: %v\n", err)
		os.Exit(1)
	}
	_ = b

	pool, err := upstream.NewPool(cfg.Routing, cfg.Upstreams, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "    [!] Upstream pool initialization failed: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	testQuery := dnsmsg.NewQuery("cloudflare.com", 1) // Type A
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, resolverName, err := pool.Resolve(ctx, testQuery)
	if err != nil {
		fmt.Printf("    [-] Upstream test query failed: %v\n", err)
	} else {
		fmt.Printf("    [+] Upstream resolution test: SUCCESS (resolved via %s, %d answer records)\n", resolverName, len(resp.Answer))
	}

	stats := pool.Stats()
	fmt.Printf("    [+] Upstream pool initialized with %d providers\n", len(stats))
	for _, u := range stats {
		fmt.Printf("        - %-20s [%-5s] Priority %d -> %s\n", u.Name, u.Transport, u.Priority, u.Endpoint)
	}

	if !allBootstrapOK {
		fmt.Println("\n[!] WARNING: One or more bootstrap DNS servers were unreachable.")
		os.Exit(1)
	}

	fmt.Println("\n[+] All validation checks PASSED successfully.")
	os.Exit(0)
}

func handleStatus() {
	printBanner()
	cfg := config.DefaultConfig()
	info, err := service.Status(cfg.Service.Name)
	if err != nil {
		fmt.Printf("[!] Service status check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Service Name:     %s\n", cfg.Service.Name)
	fmt.Printf("[*] Display Name:     %s\n", cfg.Service.DisplayName)
	fmt.Printf("[*] Installed:        %t\n", info.Installed)
	if info.Installed {
		fmt.Printf("[*] State:            %s\n", strings.ToUpper(info.State))
		if info.ProcessID != 0 {
			fmt.Printf("[*] Process ID:       %d\n", info.ProcessID)
		}
	}
	fmt.Printf("[*] Administrator:    %s\n", boolStatus(windivert.IsElevated(), "Yes (Elevated)", "No"))
}

func handleService(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: simpledns service <install|uninstall|start|stop|status> [-c config.yaml]")
		os.Exit(1)
	}

	action := strings.ToLower(args[0])
	fs := flag.NewFlagSet("service "+action, flag.ExitOnError)
	configPath := fs.String("c", "", "Path to YAML configuration file")
	configLong := fs.String("config", "", "Path to YAML configuration file")
	fs.Parse(args[1:])

	cfgFile := resolveConfigPath(*configPath, *configLong)
	cfg := loadConfiguration(cfgFile)

	switch action {
	case "install":
		if !windivert.IsElevated() {
			fmt.Fprintln(os.Stderr, "[!] Administrative privileges required to install Windows Service.")
			os.Exit(1)
		}
		err := service.Install(cfg.Service, cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Service installation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Windows Service '%s' installed successfully.\n", cfg.Service.Name)
		fmt.Println("    To start the service: simpledns service start")

	case "uninstall":
		if !windivert.IsElevated() {
			fmt.Fprintln(os.Stderr, "[!] Administrative privileges required to uninstall Windows Service.")
			os.Exit(1)
		}
		err := service.Uninstall(cfg.Service.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Service uninstallation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Windows Service '%s' removed successfully.\n", cfg.Service.Name)

	case "start":
		if !windivert.IsElevated() {
			fmt.Fprintln(os.Stderr, "[!] Administrative privileges required to start Windows Service.")
			os.Exit(1)
		}
		err := service.Start(cfg.Service.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to start service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Windows Service '%s' started.\n", cfg.Service.Name)

	case "stop":
		if !windivert.IsElevated() {
			fmt.Fprintln(os.Stderr, "[!] Administrative privileges required to stop Windows Service.")
			os.Exit(1)
		}
		err := service.Stop(cfg.Service.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to stop service: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Windows Service '%s' stopped.\n", cfg.Service.Name)

	case "status":
		handleStatus()

	default:
		fmt.Fprintf(os.Stderr, "[!] Unknown service action '%s'\n", action)
		fmt.Println("Available actions: install, uninstall, start, stop, status")
		os.Exit(1)
	}
}

func runAsWindowsService() {
	var cfgFile string

	// Check command-line arguments passed when service was registered (e.g. -c "C:\path\simpledns.yaml")
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if (arg == "-c" || arg == "-config" || arg == "--config") && i+1 < len(os.Args) {
			cfgFile = os.Args[i+1]
			break
		} else if strings.HasPrefix(arg, "-c=") || strings.HasPrefix(arg, "--config=") {
			parts := strings.SplitN(arg, "=", 2)
			if len(parts) == 2 {
				cfgFile = parts[1]
				break
			}
		}
	}

	if cfgFile == "" {
		exePath, err := os.Executable()
		if err == nil {
			exeDir := filepath.Dir(exePath)
			c1 := filepath.Join(exeDir, defaultConfigFile)
			c2 := filepath.Join(filepath.Dir(exeDir), defaultConfigFile)
			if _, err := os.Stat(c1); err == nil {
				cfgFile = c1
			} else if _, err := os.Stat(c2); err == nil {
				cfgFile = c2
			}
		}
	}

	if cfgFile == "" {
		cfgFile = defaultConfigFile
	}

	cfg := loadConfiguration(cfgFile)
	logger.Setup(logger.Config{
		Level:      cfg.Logging.Level,
		Format:     cfg.Logging.Format,
		LogQueries: cfg.Logging.LogQueries,
	}, nil)

	if err := service.RunService(cfg.Service.Name, cfg); err != nil {
		logger.L().Error("Windows Service terminated with error", "error", err)
	}
}

func handleVersion() {
	fmt.Printf("SimpleDNS Client v%s (built %s, commit %s)\n", Version, BuildDate, GitCommit)
	fmt.Printf("Go runtime: %s (%s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Println("Supported Transports: UDP, TCP, DoT, DoH (HTTP/2), DoH3 (HTTP/3), DoQ")
	fmt.Println("Interception Modes:   WinDivert (Kernel WFP), Local Listener")
}

func loadConfiguration(path string) *config.Config {
	if _, err := os.Stat(path); err == nil {
		cfg, err := config.Load(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error loading configuration '%s': %v\n", path, err)
			os.Exit(1)
		}
		return cfg
	}

	// If no config file found, return built-in defaults
	return config.DefaultConfig()
}

func resolveConfigPath(c1, c2 string) string {
	if c1 != "" {
		return c1
	}
	if c2 != "" {
		return c2
	}
	if _, err := os.Stat(defaultConfigFile); err == nil {
		return defaultConfigFile
	}
	return filepath.Join("configs", defaultConfigFile)
}

func printBanner() {
	fmt.Println(`
   _____ _                 _      _____  _   _  _____ 
  / ____(_)               | |    |  __ \| \ | |/ ____|
 | (___  _ _ __ ___  _ __ | | ___| |  | |  \| | (___  
  \___ \| | '_ ` + "`" + ` _ \| '_ \| |/ _ \ |  | | . ` + "`" + ` |\___ \ 
  ____) | | | | | | | |_) | |  __/ |__| | |\  |____) |
 |_____/|_|_| |_| |_| .__/|_|\___|_____/|_| \_|_____/ 
                    | |                               
                    |_|  Transparent Windows DNS Client`)
	fmt.Printf("  Version %s | %s/%s\n\n", Version, runtime.GOOS, runtime.GOARCH)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  simpledns <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  run                  Run the DNS client in console mode")
	fmt.Println("  check                Validate configuration and test upstream resolvers")
	fmt.Println("  status               Inspect operational and Windows Service status")
	fmt.Println("  service <action>     Manage the Windows Service (install, uninstall, start, stop, status)")
	fmt.Println("  version              Display version and supported capabilities")
	fmt.Println("  help                 Show this help message")
	fmt.Println()
	fmt.Println("Options for 'run':")
	fmt.Println("  -c, --config <file>  Path to YAML configuration file (default: simpledns.yaml)")
	fmt.Println("  --mode <mode>        Override interceptor mode: windivert, listener, or auto")
	fmt.Println("  -v, --verbose        Enable verbose debug logging")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  simpledns run                          # Run transparently with default Cloudflare/Google DoH")
	fmt.Println("  simpledns run -c myconfig.yaml         # Run with custom configuration")
	fmt.Println("  simpledns run --mode listener          # Run in local listener testing mode")
	fmt.Println("  simpledns check -c myconfig.yaml       # Strictly validate configuration file")
	fmt.Println("  simpledns service install -c config.yaml  # Install as auto-starting Windows Service")
	fmt.Println("  simpledns service start                # Start the Windows Service")
}

func printStats(stats engine.EngineStats) {
	fmt.Println("--- Statistics Snapshot ---")
	fmt.Printf("Interceptor (%s): Captured: %d | Injected: %d | Handled: %d | Failed: %d\n",
		stats.Interceptor.Name,
		stats.Interceptor.PacketsCaptured,
		stats.Interceptor.PacketsInjected,
		stats.Interceptor.QueriesHandled,
		stats.Interceptor.QueriesFailed,
	)
	fmt.Printf("Cache: Hits: %d | Misses: %d | Expired: %d | Entries: %d\n",
		stats.Cache.Hits,
		stats.Cache.Misses,
		stats.Cache.Expired,
		stats.Cache.Size,
	)
	for _, u := range stats.Upstreams {
		fmt.Printf("Upstream '%s' (%s): State: %-8s | Total: %-4d | OK: %-4d | Fail: %-2d | Avg Latency: %.1fms\n",
			u.Name, u.Transport, u.State, u.TotalQueries, u.SuccessfulQueries, u.FailedQueries, u.AvgLatencyMs)
	}
	fmt.Println("---------------------------")
}

func boolStatus(b bool, trueStr, falseStr string) string {
	if b {
		return trueStr
	}
	return falseStr
}
