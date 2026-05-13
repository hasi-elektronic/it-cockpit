// Hasi IT-Cockpit Agent v0.2.0
//
// Cross-platform endpoint monitoring agent.
// Reports inventory + telemetry + security status every 15 minutes.
//
// Build:
//   GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o hasi-agent-windows-amd64.exe ./cmd/agent
//   GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o hasi-agent-darwin-amd64 ./cmd/agent
//   GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o hasi-agent-linux-amd64 ./cmd/agent
//
// Config file (JSON):
//   {
//     "enroll_token": "ENR-...",
//     "api_url": "https://it-cockpit-api.hguencavdi.workers.dev/api",
//     "heartbeat_seconds": 900
//   }
//
// Persisted state (after register):
//   {
//     "agent_token": "AGT-...",
//     "device_id": 42,
//     "registered_at": "..."
//   }

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const AgentVersion = "0.6.1"

// ==================== Static Inventory (cross-platform) ====================

type StaticInventory struct {
	Manufacturer string
	Model        string
	SerialNumber string
	CPU          string
	RAMGb        float64
	StorageGb    float64
	OS           string
}

// ==================== Config & State ====================

type Config struct {
	EnrollToken      string `json:"enroll_token"`
	APIURL           string `json:"api_url"`
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
}

type State struct {
	AgentToken         string `json:"agent_token"`
	DeviceID           int    `json:"device_id"`
	TenantID           int    `json:"tenant_id"`
	RegisteredAt       string `json:"registered_at"`
	LastInventoryAt    string `json:"last_inventory_at,omitempty"`  // v0.6.1
}

func configDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramFiles"), "HasiCockpit")
	case "darwin":
		return "/Library/Application Support/HasiCockpit"
	default:
		return "/etc/hasi-cockpit"
	}
}

func loadConfig() (*Config, error) {
	path := filepath.Join(configDir(), "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config nicht gefunden (%s): %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config JSON-Fehler: %w", err)
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 900
	}
	return &c, nil
}

func loadState() *State {
	path := filepath.Join(configDir(), "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s State
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	return &s
}

func saveState(s *State) error {
	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configDir(), "state.json"), data, 0600)
}

// ==================== Models ====================

type RegisterPayload struct {
	EnrollToken  string  `json:"enroll_token"`
	Hostname     string  `json:"hostname"`
	OSPlatform   string  `json:"os_platform"`
	AgentVersion string  `json:"agent_version"`
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	SerialNumber string  `json:"serial_number,omitempty"`
	CPU          string  `json:"cpu,omitempty"`
	RAMGb        float64 `json:"ram_gb,omitempty"`
	StorageGb    float64 `json:"storage_gb,omitempty"`
	OS           string  `json:"os,omitempty"`
	MACAddress   string  `json:"mac_address,omitempty"`
}

type RegisterResponse struct {
	AgentToken              string `json:"agent_token"`
	AgentID                 int    `json:"agent_id"`
	DeviceID                int    `json:"device_id"`
	TenantID                int    `json:"tenant_id"`
	HeartbeatIntervalSecond int    `json:"heartbeat_interval_seconds"`
}

type AVProductInfo struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	UpToDate     bool   `json:"up_to_date"`
	IsDefender   bool   `json:"is_defender"`
	ProductState int64  `json:"product_state,omitempty"`
}

type SecurityStatus struct {
	BitlockerEnabled    bool   `json:"bitlocker_enabled"`
	BitlockerStatus     string `json:"bitlocker_status,omitempty"`
	AVProduct           string `json:"av_product,omitempty"` // primary (best-of), backward compat
	AVEnabled           bool   `json:"av_enabled"`
	AVUpToDate          bool   `json:"av_up_to_date"`
	AVSignatureAgeDays  int    `json:"av_signature_age_days,omitempty"`
	AVProducts          []AVProductInfo `json:"av_products,omitempty"` // v0.5.2: alle erkannten
	WULastSearch        string `json:"wu_last_search,omitempty"`
	WULastInstall       string `json:"wu_last_install,omitempty"`
	WUPendingCount      int    `json:"wu_pending_count"`
	WUCriticalCount     int    `json:"wu_critical_count"`
	TPMPresent          bool   `json:"tpm_present"`
	TPMReady            bool   `json:"tpm_ready"`
	SecureBoot          bool   `json:"secure_boot"`
	FirewallDomain      bool   `json:"firewall_domain"`
	FirewallPrivate     bool   `json:"firewall_private"`
	FirewallPublic      bool   `json:"firewall_public"`
	// v0.5.0 additions
	DefenderTamperOn    bool   `json:"defender_tamper_on"`
	UACEnabled          bool   `json:"uac_enabled"`
	RDPEnabled          bool   `json:"rdp_enabled"`
	AutoLoginEnabled    bool   `json:"auto_login_enabled"`
	PendingReboot       bool   `json:"pending_reboot"`
	PendingRebootReason string `json:"pending_reboot_reason,omitempty"`
	FailedLogons24h     int    `json:"failed_logons_24h"`
	LocalAdminCount     int    `json:"local_admin_count"`
	OpenPortsCount      int    `json:"open_ports_count"`
	OpenPortsList       string `json:"open_ports_list,omitempty"` // comma-separated (legacy)
	OpenPortsDetail     string `json:"open_ports_detail,omitempty"` // JSON array: [{port,proto,proc,pid}]
	LocalAdminsList     string `json:"local_admins_list,omitempty"` // JSON array of names
}

type DiskInfo struct {
	Mount       string  `json:"mount"`        // e.g. "C:"
	Label       string  `json:"label,omitempty"`
	FileSystem  string  `json:"filesystem,omitempty"`
	TotalGb     float64 `json:"total_gb"`
	FreeGb      float64 `json:"free_gb"`
	Percent     float64 `json:"percent"`
	SMARTHealth string  `json:"smart_health,omitempty"` // Healthy / Warning / Unhealthy / Unknown
	Type        string  `json:"type,omitempty"`         // SSD / HDD / NVMe / USB
}

type ProcessInfo struct {
	Name    string  `json:"name"`
	PID     int     `json:"pid"`
	RAMMb   float64 `json:"ram_mb"`
	CPUPct  float64 `json:"cpu_pct,omitempty"`
}

type BrowserInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Outdated bool  `json:"outdated"`
}

type SoftwareItem struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
}

type HeartbeatPayload struct {
	UptimeSeconds  int64           `json:"uptime_seconds,omitempty"`
	LoggedInUser   string          `json:"logged_in_user,omitempty"`
	CPUPercent     float64         `json:"cpu_percent,omitempty"`
	RAMPercent     float64         `json:"ram_percent,omitempty"`
	RAMTotalGb     float64         `json:"ram_total_gb,omitempty"`
	RAMUsedGb      float64         `json:"ram_used_gb,omitempty"`
	DiskCPercent   float64         `json:"disk_c_percent,omitempty"`
	DiskCTotalGb   float64         `json:"disk_c_total_gb,omitempty"`
	DiskCFreeGb    float64         `json:"disk_c_free_gb,omitempty"`
	IPInternal     string          `json:"ip_internal,omitempty"`
	LastBoot       string          `json:"last_boot,omitempty"`
	Security       *SecurityStatus `json:"security,omitempty"`
	Software       []SoftwareItem  `json:"software,omitempty"`
	// v0.5.0 additions
	Disks          []DiskInfo      `json:"disks,omitempty"`
	TopProcesses   []ProcessInfo   `json:"top_processes,omitempty"`
	Browsers       []BrowserInfo   `json:"browsers,omitempty"`
	CPUTempC       float64         `json:"cpu_temp_c,omitempty"`
	BatteryWearPct float64         `json:"battery_wear_pct,omitempty"`
	BatteryHealth  string          `json:"battery_health,omitempty"`
	BootTimeSec    int             `json:"boot_time_sec,omitempty"`
	OutdatedSwCount int            `json:"outdated_sw_count,omitempty"`
	// v0.5.12: AnyDesk ID for remote support
	AnyDeskID      string          `json:"anydesk_id,omitempty"`
	// v0.6.1: Static inventory (sent once per day; backfills bulk-enrolled devices)
	Manufacturer   string          `json:"manufacturer,omitempty"`
	Model          string          `json:"model,omitempty"`
	SerialNumber   string          `json:"serial_number,omitempty"`
	CPU            string          `json:"cpu,omitempty"`
	RAMGbTotal     float64         `json:"ram_gb,omitempty"`
	StorageGbTotal float64         `json:"storage_gb,omitempty"`
	OSVersion      string          `json:"os_version,omitempty"`
	MACAddress     string          `json:"mac_address,omitempty"`
}

// ==================== HTTP ====================

var httpClient = &http.Client{Timeout: 30 * time.Second}

func postJSON(url string, payload interface{}, headers map[string]string) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HasiCockpitAgent/"+AgentVersion)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func getJSON(url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "HasiCockpitAgent/"+AgentVersion)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// ==================== Common Collectors ====================

func getHostname() string {
	h, _ := os.Hostname()
	return h
}

func getPrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

func getPrimaryMAC() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.HardwareAddr == nil {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac != "" && !strings.HasPrefix(mac, "00:00:00") {
			return mac
		}
	}
	return ""
}

// ==================== Register Flow ====================

func register(cfg *Config) (*State, error) {
	hw := collectStaticInventory()
	payload := RegisterPayload{
		EnrollToken:  cfg.EnrollToken,
		Hostname:     getHostname(),
		OSPlatform:   runtime.GOOS,
		AgentVersion: AgentVersion,
		Manufacturer: hw.Manufacturer,
		Model:        hw.Model,
		SerialNumber: hw.SerialNumber,
		CPU:          hw.CPU,
		RAMGb:        hw.RAMGb,
		StorageGb:    hw.StorageGb,
		OS:           hw.OS,
		MACAddress:   getPrimaryMAC(),
	}

	body, status, err := postJSON(cfg.APIURL+"/agent/register", payload, nil)
	if err != nil {
		return nil, fmt.Errorf("register HTTP failed: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("register status %d: %s", status, string(body))
	}

	var resp RegisterResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("register response parse: %w", err)
	}

	state := &State{
		AgentToken:   resp.AgentToken,
		DeviceID:     resp.DeviceID,
		TenantID:     resp.TenantID,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveState(state); err != nil {
		log.Printf("WARN: state could not be saved: %v", err)
	}
	if resp.HeartbeatIntervalSecond > 0 {
		cfg.HeartbeatSeconds = resp.HeartbeatIntervalSecond
	}
	return state, nil
}

// ==================== Heartbeat Loop ====================

func sendHeartbeat(cfg *Config, state *State) error {
	payload := collectHeartbeat()
	body, status, err := postJSON(cfg.APIURL+"/agent/heartbeat", payload, map[string]string{
		"X-Agent-Token": state.AgentToken,
	})
	if err != nil {
		return fmt.Errorf("heartbeat HTTP: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("heartbeat status %d: %s", status, string(body))
	}
	return nil
}

// ==================== Main ====================

func main() {
	var (
		serviceMode = flag.Bool("service", false, "Run as service (no console output)")
		onceMode    = flag.Bool("once", false, "Send single heartbeat and exit (for testing)")
		registerOnly = flag.Bool("register", false, "Register only, do not start heartbeat loop")
		showVersion = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Hasi IT-Cockpit Agent v%s (%s/%s)\n", AgentVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	// Setup logging
	if *serviceMode {
		logPath := filepath.Join(configDir(), "agent.log")
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.SetOutput(f)
		}
	}
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.Printf("Hasi Agent v%s starting (mode=service:%v)", AgentVersion, *serviceMode)

	// Load config
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Config: %v", err)
	}
	log.Printf("Config loaded. API: %s. Heartbeat: %ds", cfg.APIURL, cfg.HeartbeatSeconds)

	// Load or register
	state := loadState()
	if state == nil || state.AgentToken == "" {
		log.Printf("No state found, registering...")
		var err error
		state, err = register(cfg)
		if err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		log.Printf("Registered. Device ID: %d. Tenant: %d", state.DeviceID, state.TenantID)
	} else {
		log.Printf("State loaded. Device ID: %d", state.DeviceID)
	}

	if *registerOnly {
		log.Printf("Register-only mode. Exiting.")
		return
	}

	// First heartbeat immediately
	if err := sendHeartbeatWithUpdate(cfg, state); err != nil {
		log.Printf("Initial heartbeat failed: %v", err)
	} else {
		log.Printf("Initial heartbeat OK")
	}
	// First command poll
	pollCommands(cfg, state)

	if *onceMode {
		log.Printf("Once-mode. Exiting.")
		return
	}

	// Main loops: slow heartbeat (every cfg.HeartbeatSeconds) + fast command poll (30s)
	hbInterval := time.Duration(cfg.HeartbeatSeconds) * time.Second
	cmdInterval := 30 * time.Second
	log.Printf("Entering loop (heartbeat=%v, command-poll=%v)", hbInterval, cmdInterval)

	hbTicker := time.NewTicker(hbInterval)
	cmdTicker := time.NewTicker(cmdInterval)
	defer hbTicker.Stop()
	defer cmdTicker.Stop()

	for {
		select {
		case <-hbTicker.C:
			if err := sendHeartbeatWithUpdate(cfg, state); err != nil {
				log.Printf("Heartbeat error: %v", err)
			} else {
				log.Printf("Heartbeat OK")
			}
			// Heartbeat also triggers a command poll
			pollCommands(cfg, state)
		case <-cmdTicker.C:
			pollCommands(cfg, state)
		}
	}
}
