package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Build-time variables (set via -ldflags). For the generic build, only
// the public URLs are baked in. TenantSlug + TenantName + BulkToken are
// resolved at runtime: slug from filename (hasi-install-<slug>.exe),
// name + token from GET /api/install/<slug>/bulk-token.
var (
	TenantSlug = ""       // resolved from os.Args[0] filename
	TenantName = ""       // resolved from /api/install/<slug>/bulk-token
	BulkToken  = ""       // resolved from /api/install/<slug>/bulk-token
	APIBase    = "https://it-cockpit-api.hguencavdi.workers.dev/api"
	Origin     = "https://it-cockpit-api.hguencavdi.workers.dev"
	CockpitURL = "https://it-cockpit.pages.dev"
	Version    = "0.8.5"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[97m"
	colorGray    = "\033[90m"
	bold         = "\033[1m"
)

func main() {
	silent := flag.Bool("silent", false, "Silent install (no pause at end)")
	noElevate := flag.Bool("no-elevate", false, "Skip self-elevation check (internal)")
	flag.Parse()

	// Enable ANSI colors on Windows
	enableColors()

	// Self-elevate
	if runtime.GOOS == "windows" && !*noElevate && !isAdmin() {
		fmt.Println("")
		fmt.Println("  Administrator-Rechte werden angefordert...")
		fmt.Println("")
		if err := elevate(); err != nil {
			fmt.Printf("\n  FEHLER: Selbst-Elevation fehlgeschlagen: %v\n", err)
			fmt.Println("\n  Manuelle Loesung: Rechtsklick auf diese .exe -> 'Als Administrator ausfuehren'")
			pause()
			os.Exit(1)
		}
		// elevated process started; this instance exits
		os.Exit(0)
	}

	banner()

	hostname, _ := os.Hostname()
	username := getUsername()
	fmt.Printf("  %sHostname:%s  %s%s%s\n", colorGray, colorReset, colorWhite, hostname, colorReset)
	fmt.Printf("  %sBenutzer:%s  %s%s%s\n", colorGray, colorReset, colorWhite, username, colorReset)
	fmt.Println()

	// v0.8.5: Resolve tenant context at runtime instead of bake-time.
	// 1) Slug is parsed from os.Args[0] filename (e.g. "hasi-install-sickinger.exe" -> "sickinger")
	// 2) Token + name are fetched from GET /api/install/<slug>/bulk-token
	// This way token rotation does NOT require an installer rebuild.
	if TenantSlug == "" {
		resolved, err := resolveSlugFromFilename()
		if err != nil {
			fmt.Printf("\n  %sFEHLER:%s Mandant konnte nicht aus Dateinamen ermittelt werden.\n", colorRed, colorReset)
			fmt.Printf("  Dateiname muss dem Muster 'hasi-install-<mandant>.exe' folgen.\n")
			fmt.Printf("  Gefunden: %s\n", filepath.Base(os.Args[0]))
			fmt.Printf("  Detail: %v\n", err)
			pause()
			os.Exit(1)
		}
		TenantSlug = resolved
	}

	if BulkToken == "" {
		fmt.Printf("  %sErmittle Mandanten-Konfiguration fuer '%s'...%s\n", colorGray, TenantSlug, colorReset)
		info, err := fetchTenantInfo(TenantSlug)
		if err != nil {
			fmt.Printf("\n  %sFEHLER:%s Mandanten-Konfiguration nicht abrufbar.\n", colorRed, colorReset)
			fmt.Printf("  Mandant: %s\n", TenantSlug)
			fmt.Printf("  Detail: %v\n", err)
			fmt.Printf("\n  Pruefe:\n")
			fmt.Printf("    - Internet-Verbindung\n")
			fmt.Printf("    - Mandant existiert und ist aktiviert\n")
			fmt.Printf("    - Cockpit-Dienst erreichbar: %s\n", Origin)
			pause()
			os.Exit(1)
		}
		BulkToken = info.BulkToken
		TenantName = info.TenantName
	}

	// Show resolved tenant
	if TenantName != "" {
		fmt.Printf("  %sMandant:%s   %s%s%s\n", colorGray, colorReset, colorWhite, TenantName, colorReset)
	} else {
		fmt.Printf("  %sMandant:%s   %s%s%s\n", colorGray, colorReset, colorWhite, TenantSlug, colorReset)
	}
	fmt.Println()

	installDir := `C:\Program Files\HasiCockpit`
	exePath := filepath.Join(installDir, "hasi-agent.exe")
	configPath := filepath.Join(installDir, "config.json")
	statePath := filepath.Join(installDir, "state.json")
	logPath := filepath.Join(installDir, "install.log")
	taskName := "HasiCockpitAgent"

	logBuf := &bytes.Buffer{}
	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(logBuf, "[%s] "+format+"\n", append([]interface{}{time.Now().UTC().Format(time.RFC3339)}, args...)...)
	}
	logf("Installer started v%s for tenant=%s", Version, TenantSlug)
	logf("Hostname=%s User=%s", hostname, username)

	// Step 1: Stop existing
	step(1, 6, "Pruefe bestehenden Agent...")
	stopExistingAgent(taskName, logf)

	// Step 2: Create install dir
	step(2, 6, "Erstelle Installations-Verzeichnis...")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		fail("Verzeichnis konnte nicht erstellt werden: "+err.Error(), logBuf.String(), logPath)
	}
	ok(installDir)
	logf("MkDir OK: %s", installDir)

	// Step 3: Download agent
	step(3, 6, "Lade neuesten Agent herunter...")
	binaryURL := Origin + "/agent-binary/hasi-agent-windows-amd64.exe"
	size, err := downloadFile(binaryURL, exePath)
	if err != nil {
		fail("Download fehlgeschlagen: "+err.Error(), logBuf.String(), logPath)
	}
	ok(fmt.Sprintf("%.1f MB heruntergeladen", float64(size)/1024/1024))
	logf("Download OK: %s -> %s (%d bytes)", binaryURL, exePath, size)

	// Step 4: Bulk enroll
	step(4, 6, fmt.Sprintf("Registriere Geraet '%s'...", hostname))
	enrollResp, err := bulkEnroll(hostname)
	if err != nil {
		fail("Enrollment fehlgeschlagen: "+err.Error(), logBuf.String(), logPath)
	}
	ok(fmt.Sprintf("Device ID: %d (%s)", enrollResp.DeviceID, enrollResp.Action))
	logf("Enroll OK: device_id=%d action=%s", enrollResp.DeviceID, enrollResp.Action)

	// Step 5: Write config
	step(5, 6, "Schreibe Konfiguration...")
	cfg := map[string]interface{}{
		"api_url":                    APIBase,
		"agent_token":                enrollResp.AgentToken,
		"heartbeat_interval_seconds": 900,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, cfgJSON, 0644); err != nil {
		fail("config.json konnte nicht geschrieben werden: "+err.Error(), logBuf.String(), logPath)
	}
	// state.json — agent needs agent_token here (struct: agent_token, device_id, tenant_id)
	st := map[string]interface{}{
		"agent_token": enrollResp.AgentToken,
		"device_id":   enrollResp.DeviceID,
		"tenant_id":   enrollResp.TenantID,
	}
	stJSON, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(statePath, stJSON, 0644)
	ok("config.json + state.json geschrieben")
	logf("Config written")

	// Step 6: Task Scheduler
	step(6, 6, "Konfiguriere Task Scheduler...")
	if err := registerScheduledTask(taskName, exePath); err != nil {
		fail("Task Scheduler-Eintrag fehlgeschlagen: "+err.Error(), logBuf.String(), logPath)
	}
	ok(fmt.Sprintf("Task '%s' eingerichtet", taskName))
	logf("Task registered")

	// Start the scheduled task immediately (runs as SYSTEM, async — installer doesn't wait)
	fmt.Println()
	fmt.Printf("  %sStarte Agent im Hintergrund...%s\n", colorCyan, colorReset)
	startTaskNow(taskName)
	logf("Task started (background, SYSTEM context)")

	// Quick fire-and-forget heartbeat via agent (don't wait — telemetry takes 2-3 min)
	// We launch detached process and continue immediately
	go func() {
		_ = launchDetachedAgent(exePath)
	}()
	time.Sleep(1 * time.Second) // give it a moment to spawn
	ok("Agent gestartet — Heartbeat folgt in 1-3 Minuten")

	// Write install log
	_ = os.WriteFile(logPath, logBuf.Bytes(), 0644)

	// Success banner
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", bold, colorGreen, colorReset)
	fmt.Printf("  %s%s║  ✓ INSTALLATION ABGESCHLOSSEN                                ║%s\n", bold, colorGreen, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", bold, colorGreen, colorReset)
	fmt.Println()
	fmt.Printf("  %sHostname:%s    %s%s%s\n", colorGray, colorReset, colorWhite, hostname, colorReset)
	fmt.Printf("  %sDevice ID:%s   %s%d%s\n", colorGray, colorReset, colorWhite, enrollResp.DeviceID, colorReset)
	fmt.Printf("  %sAktion:%s      %s%s%s\n", colorGray, colorReset, colorWhite, enrollResp.Action, colorReset)
	fmt.Printf("  %sLog:%s         %s%s%s\n", colorGray, colorReset, colorGray, logPath, colorReset)
	fmt.Println()
	fmt.Printf("  %sCockpit:%s     %s%s%s\n", colorGray, colorReset, colorCyan, CockpitURL, colorReset)
	fmt.Println()

	if !*silent {
		fmt.Print("  Druecken Sie Enter zum Schliessen...")
		fmt.Scanln()
	} else {
		time.Sleep(3 * time.Second)
	}
}

// ---- Output helpers ----

func banner() {
	clearScreen()
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", bold, colorCyan, colorReset)
	fmt.Printf("  %s%s║  %sHASI IT-COCKPIT%s%s%s                                             %s%s║%s\n", bold, colorCyan, colorWhite, colorReset, bold, colorCyan, bold, colorCyan, colorReset)
	tenant := strings.ReplaceAll(TenantName, "_", " ")
	if len(tenant) > 54 {
		tenant = tenant[:54]
	}
	fmt.Printf("  %s%s║  %sMandant: %-54s%s%s║%s\n", bold, colorCyan, colorGray, tenant, bold, colorCyan, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", bold, colorCyan, colorReset)
	fmt.Println()
}

func step(n, total int, msg string) {
	fmt.Printf("  %s[%d/%d]%s %s%s%s\n", colorCyan, n, total, colorReset, colorWhite, msg, colorReset)
}

func ok(msg string) {
	fmt.Printf("        %s✓%s %s%s%s\n", colorGreen, colorReset, colorGray, msg, colorReset)
}

func fail(msg, logContent, logPath string) {
	_ = os.MkdirAll(filepath.Dir(logPath), 0755)
	_ = os.WriteFile(logPath, []byte(logContent+"\nFAIL: "+msg+"\n"), 0644)
	fmt.Println()
	fmt.Printf("  %s%s╔══════════════════════════════════════════════════════════════╗%s\n", bold, colorRed, colorReset)
	fmt.Printf("  %s%s║  ✗ INSTALLATION FEHLGESCHLAGEN                               ║%s\n", bold, colorRed, colorReset)
	fmt.Printf("  %s%s╚══════════════════════════════════════════════════════════════╝%s\n", bold, colorRed, colorReset)
	fmt.Println()
	fmt.Printf("  %sFehler:%s %s\n", colorYellow, colorReset, msg)
	fmt.Printf("  %sLog:%s %s\n", colorGray, colorReset, logPath)
	fmt.Println()
	pause()
	os.Exit(1)
}

func pause() {
	fmt.Print("  Druecken Sie Enter zum Schliessen...")
	fmt.Scanln()
}

// ---- Network ----

type EnrollResponse struct {
	OK         bool   `json:"ok"`
	DeviceID   int64  `json:"device_id"`
	AgentToken string `json:"agent_token"`
	TenantID   int64  `json:"tenant_id"`
	TenantSlug string `json:"tenant_slug"`
	Action     string `json:"action"`
}

func bulkEnroll(hostname string) (*EnrollResponse, error) {
	// Get tenant install token via /api/install/<slug>.token endpoint... actually we bake it in
	// at build time, OR we fetch the install script and parse... cleaner: bake the token into the installer.
	// Token comes from build-time -ldflags.
	body := map[string]interface{}{
		"bulk_token":   bulkToken(),
		"hostname":     hostname,
		"os_platform":  "windows",
		"mac_address":  getMacAddress(),
		"manufacturer": getManufacturer(),
		"model":        getModel(),
	}
	bodyJSON, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", APIBase+"/agent/bulk-enroll", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}
	var er EnrollResponse
	if err := json.Unmarshal(respBytes, &er); err != nil {
		return nil, fmt.Errorf("parse: %w (body=%s)", err, string(respBytes))
	}
	if !er.OK {
		return nil, fmt.Errorf("server returned ok=false: %s", string(respBytes))
	}
	return &er, nil
}

// bulkToken returns the current install_token. v0.8.5+: fetched at runtime
// via fetchTenantInfo() and stored in the package-level BulkToken variable.
func bulkToken() string { return BulkToken }

// resolveSlugFromFilename extracts the tenant slug from os.Args[0].
// Accepts patterns:
//
//	hasi-install-sickinger.exe          -> sickinger
//	hasi-install-sickinger-v0.8.5.exe   -> sickinger
//	hasi-install-sickinger_test.exe     -> sickinger_test
//
// Returns error if the filename does not match the expected pattern.
func resolveSlugFromFilename() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	base := filepath.Base(exe)
	// strip .exe
	name := strings.TrimSuffix(strings.ToLower(base), ".exe")
	// Expect "hasi-install-<slug>" prefix
	const prefix = "hasi-install-"
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("filename %q does not start with %q", base, prefix)
	}
	tail := strings.TrimPrefix(name, prefix)
	// Cut at first "-v" (version suffix like -v0.8.5) if present.
	if idx := strings.Index(tail, "-v"); idx > 0 {
		// Verify the part after -v looks like a version (digit/dot)
		rest := tail[idx+2:]
		if len(rest) > 0 && (rest[0] >= '0' && rest[0] <= '9') {
			tail = tail[:idx]
		}
	}
	tail = strings.TrimSpace(tail)
	if tail == "" {
		return "", fmt.Errorf("filename %q has empty slug part", base)
	}
	// Slug must match [a-z0-9_-]+
	for _, c := range tail {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return "", fmt.Errorf("filename %q contains invalid slug characters: %q", base, tail)
		}
	}
	return tail, nil
}

// tenantInfo is the JSON response from /api/install/<slug>/bulk-token.
type tenantInfo struct {
	Slug       string `json:"slug"`
	TenantName string `json:"tenant_name"`
	BulkToken  string `json:"bulk_token"`
}

// fetchTenantInfo retrieves the current bulk-token + display name for a
// given slug. This is the v0.8.5 runtime replacement for the bake-time
// -ldflags injection. Token rotation no longer needs a rebuild.
func fetchTenantInfo(slug string) (*tenantInfo, error) {
	url := APIBase + "/install/" + slug + "/bulk-token"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "HasiInstaller/"+Version)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("Mandant '%s' nicht gefunden oder nicht aktiviert", slug)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var info tenantInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse JSON: %w (body=%s)", err, string(body))
	}
	if info.BulkToken == "" {
		return nil, fmt.Errorf("Server lieferte leeren Token")
	}
	return &info, nil
}

func downloadFile(url, dst string) (int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, resp.Body)
}

// ---- Agent control ----

func stopExistingAgent(taskName string, logf func(string, ...interface{})) {
	if runtime.GOOS != "windows" {
		return
	}
	cmd := exec.Command("schtasks", "/End", "/TN", taskName)
	_ = cmd.Run()

	// Kill running processes
	cmd2 := exec.Command("taskkill", "/F", "/IM", "hasi-agent.exe")
	cmd2.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd2.Run()

	time.Sleep(2 * time.Second)
	logf("Existing agent stopped (if any)")
}

func registerScheduledTask(taskName, exePath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("only windows supported")
	}

	// Use schtasks command for reliable Task Scheduler creation
	// Delete existing first
	delCmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = delCmd.Run()

	// Create new — Run as SYSTEM, every 15 minutes, indefinitely
	createCmd := exec.Command(
		"schtasks", "/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s"`, exePath),
		"/SC", "MINUTE",
		"/MO", "15",
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	createCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Create failed: %w (output: %s)", err, string(out))
	}

	return nil
}

func runAgentOnce(exePath string) (string, error) {
	cmd := exec.Command(exePath, "--once")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// launchDetachedAgent starts hasi-agent.exe --once as a fully detached
// background process. The installer doesn't wait for it to finish.
// Telemetry collection takes 2-3 minutes, but Task Scheduler will pick
// up next runs automatically.
func launchDetachedAgent(exePath string) error {
	cmd := exec.Command(exePath, "--once")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x00000008, // DETACHED_PROCESS
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Don't wait — let it run in background
	go cmd.Wait()
	return nil
}

func startTaskNow(taskName string) {
	cmd := exec.Command("schtasks", "/Run", "/TN", taskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

// ---- System info ----

func getUsername() string {
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "unknown"
}

func getMacAddress() string {
	// Best-effort via PowerShell
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1).MacAddress").Output()
	return strings.TrimSpace(string(out))
}

func getManufacturer() string {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Manufacturer").Output()
	return strings.TrimSpace(string(out))
}

func getModel() string {
	out, _ := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Model").Output()
	return strings.TrimSpace(string(out))
}

// ---- Admin elevation (Windows) ----

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func elevate() error {
	if runtime.GOOS != "windows" {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Use ShellExecute via PowerShell to trigger UAC
	cmd := exec.Command("powershell", "-Command",
		fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList '--no-elevate' -Verb RunAs`, exe))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func enableColors() {
	// On modern Windows 10+, ANSI is supported; older versions just see escape codes.
	// We leave them — they're tolerable.
}
