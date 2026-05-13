package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// UpdateInfo mirrors the `update` block from heartbeat response.
type UpdateInfo struct {
	Available      bool   `json:"available"`
	LatestVersion  string `json:"latest_version"`
	CurrentVersion string `json:"current_version"`
	DownloadURL    string `json:"download_url"`
	SHA256         string `json:"sha256"`
	SizeBytes      int64  `json:"size_bytes"`
	Required       bool   `json:"required"`
}

type HeartbeatResponse struct {
	OK                   bool        `json:"ok"`
	NextHeartbeatSeconds int         `json:"next_heartbeat_seconds"`
	Update               *UpdateInfo `json:"update"`
}

// performSelfUpdate downloads new binary, verifies, replaces self, restarts.
// Returns nil on success (process will exit shortly after this returns).
func performSelfUpdate(update *UpdateInfo) error {
	if update == nil || !update.Available || update.DownloadURL == "" {
		return fmt.Errorf("no update info")
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("self-update currently only supported on Windows")
	}

	log.Printf("[update] starting upgrade from %s -> %s", update.CurrentVersion, update.LatestVersion)

	// 1. Determine paths
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	currentExe, _ = filepath.EvalSymlinks(currentExe)
	exeDir := filepath.Dir(currentExe)
	newPath := filepath.Join(exeDir, fmt.Sprintf("hasi-agent-%s.exe.new", update.LatestVersion))
	oldBackupPath := filepath.Join(exeDir, "hasi-agent.old.exe")

	// 2. Download new binary to .new
	log.Printf("[update] downloading from %s", update.DownloadURL)
	resp, err := httpClientShort().Get(update.DownloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download status %d", resp.StatusCode)
	}

	out, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	hasher := sha256.New()
	tee := io.MultiWriter(out, hasher)
	written, err := io.Copy(tee, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(newPath)
		return fmt.Errorf("write: %w", err)
	}
	log.Printf("[update] downloaded %d bytes", written)

	// 3. Verify SHA-256 if server provided one
	if update.SHA256 != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != update.SHA256 {
			os.Remove(newPath)
			return fmt.Errorf("sha256 mismatch: expected %s, got %s", update.SHA256, actual)
		}
		log.Printf("[update] sha256 verified: %s", actual)
	} else {
		log.Printf("[update] no sha256 provided by server, skipping integrity check")
	}

	// 4. Smoke-test the new binary: --version should print and exit 0
	cmd := exec.Command(newPath, "--version")
	if smokeOut, err := cmd.CombinedOutput(); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("new binary smoke test failed: %w (%s)", err, string(smokeOut))
	}
	log.Printf("[update] new binary smoke test passed")

	// 5. Swap files: current.exe -> .old.exe, .new -> current.exe
	// Windows: rename of running .exe is fine (file handles remain valid until close)
	os.Remove(oldBackupPath) // clean any previous backup
	if err := os.Rename(currentExe, oldBackupPath); err != nil {
		os.Remove(newPath)
		return fmt.Errorf("backup rename: %w", err)
	}
	if err := os.Rename(newPath, currentExe); err != nil {
		// Try to restore
		os.Rename(oldBackupPath, currentExe)
		return fmt.Errorf("install rename: %w", err)
	}
	log.Printf("[update] binary swapped")

	// 6. Launch new binary as detached process, then exit current.
	// The scheduled task / service will pick up the new exe on next heartbeat cycle.
	// For immediate effect, start a one-shot heartbeat in detached mode.
	startCmd := exec.Command(currentExe, "--once")
	startCmd.SysProcAttr = detachedSysProcAttr()
	if err := startCmd.Start(); err != nil {
		log.Printf("[update] warning: failed to spawn new binary: %v (scheduled task will pick it up)", err)
	} else {
		log.Printf("[update] new binary launched (PID %d)", startCmd.Process.Pid)
	}

	// 7. Schedule old backup deletion (best effort)
	go func() {
		time.Sleep(30 * time.Second)
		os.Remove(oldBackupPath)
	}()

	log.Printf("[update] upgrade complete, exiting old process")
	return nil
}

// sendHeartbeatWithUpdate sends a heartbeat and processes any update info in the response.
// If update succeeds, this function calls os.Exit(0) so the new binary takes over.
func sendHeartbeatWithUpdate(cfg *Config, state *State) error {
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

	// Parse response for update directive
	var resp HeartbeatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// Not JSON or schema mismatch — heartbeat still succeeded
		return nil
	}

	if resp.Update != nil && resp.Update.Available {
		log.Printf("[update] server signals new version available: %s (current %s, required=%v)",
			resp.Update.LatestVersion, resp.Update.CurrentVersion, resp.Update.Required)

		if err := performSelfUpdate(resp.Update); err != nil {
			log.Printf("[update] FAILED: %v", err)
			// Don't propagate — heartbeat itself was fine
		} else {
			log.Printf("[update] success, exiting to let new binary take over")
			os.Exit(0)
		}
	}

	return nil
}

func httpClientShort() *http.Client {
	return &http.Client{Timeout: 5 * time.Minute} // large for binary download
}
