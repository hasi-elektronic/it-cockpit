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

// Build-time variables (set via -ldflags)
var (
	TenantSlug = "sickinger" // default, override at build: -X main.TenantSlug=xxx
	TenantName = "Manfred Sickinger GmbH"
	APIBase    = "https://it-cockpit-api.hguencavdi.workers.dev/api"
	Origin     = "https://it-cockpit-api.hguencavdi.workers.dev"
	CockpitURL = "https://it-cockpit.pages.dev"
	Version    = "1.0.0"
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
	st := map[string]interface{}{"device_id": enrollResp.DeviceID}
	stJSON, _ := json.Marshal(st)
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

	// First heartbeat (verbose)
	fmt.Println()
	fmt.Printf("  %sSende ersten Heartbeat...%s\n", colorCyan, colorReset)
	hbOutput, hbErr := runAgentOnce(exePath)
	logf("Heartbeat output:\n%s", hbOutput)
	if hbErr != nil {
		fmt.Printf("        %s⚠ Heartbeat-Fehler: %v%s\n", colorYellow, hbErr, colorReset)
		fmt.Printf("        %sTask laeuft trotzdem in 15 Min automatisch%s\n", colorGray, colorReset)
		logf("Heartbeat error: %v", hbErr)
	} else {
		fmt.Printf("        %s✓ Heartbeat erfolgreich%s\n", colorGreen, colorReset)
		if strings.TrimSpace(hbOutput) != "" {
			for _, line := range strings.Split(strings.TrimSpace(hbOutput), "\n") {
				fmt.Printf("          %s%s%s\n", colorGray, strings.TrimSpace(line), colorReset)
			}
		}
	}

	// Force scheduled task run for SYSTEM-context first run
	startTaskNow(taskName)

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

// Token baked at build time via -ldflags -X
var BulkToken = ""

func bulkToken() string { return BulkToken }

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
