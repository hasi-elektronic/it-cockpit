//go:build darwin

package main

import (
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ==================== STATIC INVENTORY ====================
func collectStaticInventory() *StaticInventory {
	inv := &StaticInventory{}
	// Manufacturer = Apple
	inv.Manufacturer = "Apple"

	// Model name via sysctl
	inv.Model = runCmd("sysctl", "-n", "hw.model")

	// Serial via ioreg
	out := runCmd("/bin/sh", "-c", `ioreg -l | awk -F'"' '/IOPlatformSerialNumber/ { print $4 }'`)
	inv.SerialNumber = strings.TrimSpace(out)

	// CPU brand
	inv.CPU = runCmd("sysctl", "-n", "machdep.cpu.brand_string")

	// RAM
	memBytes := runCmd("sysctl", "-n", "hw.memsize")
	if v, err := strconv.ParseFloat(memBytes, 64); err == nil {
		inv.RAMGb = float64(int((v / (1024 * 1024 * 1024)) + 0.5))
	}

	// Storage (root)
	dfOut := runCmd("/bin/sh", "-c", "df -k / | tail -1 | awk '{print $2}'")
	if v, err := strconv.ParseFloat(dfOut, 64); err == nil {
		inv.StorageGb = float64(int((v / (1024 * 1024)) + 0.5))
	}

	// OS
	osName := runCmd("sw_vers", "-productName")
	osVer := runCmd("sw_vers", "-productVersion")
	osBuild := runCmd("sw_vers", "-buildVersion")
	inv.OS = strings.TrimSpace(osName + " " + osVer + " (" + osBuild + ")")
	return inv
}

// ==================== HEARTBEAT ====================
func collectHeartbeat() *HeartbeatPayload {
	hb := &HeartbeatPayload{IPInternal: getPrimaryIP()}
	// Logged-in user (console user)
	hb.LoggedInUser = runCmd("/bin/sh", "-c", "stat -f%Su /dev/console")

	// Last boot from sysctl
	boot := runCmd("sysctl", "-n", "kern.boottime")
	// Format: "{ sec = 1715234567, usec = 0 } Mon Mar ..."
	if idx := strings.Index(boot, "sec ="); idx >= 0 {
		rest := boot[idx+5:]
		if comma := strings.Index(rest, ","); comma > 0 {
			secStr := strings.TrimSpace(rest[:comma])
			if sec, err := strconv.ParseInt(secStr, 10, 64); err == nil {
				bootTime := time.Unix(sec, 0).UTC()
				hb.LastBoot = bootTime.Format("2006-01-02T15:04:05Z")
				hb.UptimeSeconds = int64(time.Since(bootTime).Seconds())
			}
		}
	}

	// CPU usage via top
	cpuLine := runCmd("/bin/sh", "-c", "top -l 1 -n 0 | awk '/CPU usage/ { gsub(\"%\",\"\"); print $3 }'")
	hb.CPUPercent, _ = strconv.ParseFloat(cpuLine, 64)

	// RAM
	memBytes := runCmd("sysctl", "-n", "hw.memsize")
	if total, err := strconv.ParseFloat(memBytes, 64); err == nil {
		hb.RAMTotalGb = total / (1024 * 1024 * 1024)
		// Used via vm_stat
		vmOut := runCmd("vm_stat")
		var pagesActive, pagesWired, pagesCompressed float64
		var pageSize float64 = 4096
		for _, line := range strings.Split(vmOut, "\n") {
			if strings.Contains(line, "page size of") {
				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "of" && i+1 < len(parts) {
						pageSize, _ = strconv.ParseFloat(parts[i+1], 64)
					}
				}
			} else if strings.HasPrefix(line, "Pages active:") {
				pagesActive = parsePagesValue(line)
			} else if strings.HasPrefix(line, "Pages wired down:") {
				pagesWired = parsePagesValue(line)
			} else if strings.HasPrefix(line, "Pages occupied by compressor:") {
				pagesCompressed = parsePagesValue(line)
			}
		}
		usedBytes := (pagesActive + pagesWired + pagesCompressed) * pageSize
		hb.RAMUsedGb = usedBytes / (1024 * 1024 * 1024)
		if total > 0 {
			hb.RAMPercent = (usedBytes / total) * 100
		}
	}

	// Disk (root)
	dfOut := runCmd("/bin/sh", "-c", "df -k / | tail -1 | awk '{print $2\"|\"$4}'")
	if parts := strings.SplitN(dfOut, "|", 2); len(parts) == 2 {
		total, _ := strconv.ParseFloat(parts[0], 64)
		free, _ := strconv.ParseFloat(parts[1], 64)
		if total > 0 {
			hb.DiskCTotalGb = total / (1024 * 1024)
			hb.DiskCFreeGb = free / (1024 * 1024)
			hb.DiskCPercent = ((total - free) / total) * 100
		}
	}

	// Security (macOS — basic)
	hb.Security = collectDarwinSecurity()
	hb.Software = collectDarwinSoftware()
	return hb
}

func parsePagesValue(line string) float64 {
	// "Pages active: 12345."
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return 0
	}
	last := parts[len(parts)-1]
	last = strings.TrimSuffix(last, ".")
	v, _ := strconv.ParseFloat(last, 64)
	return v
}

func collectDarwinSecurity() *SecurityStatus {
	sec := &SecurityStatus{}

	// FileVault (BitLocker equivalent)
	fv := runCmd("fdesetup", "status")
	if strings.Contains(fv, "FileVault is On") {
		sec.BitlockerEnabled = true
		sec.BitlockerStatus = "FileVault On"
	} else if strings.Contains(fv, "FileVault is Off") {
		sec.BitlockerStatus = "FileVault Off"
	}

	// SIP (Secure Boot equivalent on macOS)
	sip := runCmd("csrutil", "status")
	sec.SecureBoot = strings.Contains(sip, "enabled")

	// Firewall (Application Layer)
	fw := runCmd("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	if fw == "1" || fw == "2" {
		sec.FirewallDomain = true
		sec.FirewallPrivate = true
		sec.FirewallPublic = true
	}

	// XProtect (macOS built-in AV)
	xp := runCmd("/bin/sh", "-c", "ls /Library/Apple/System/Library/CoreServices/XProtect.bundle 2>/dev/null")
	if xp != "" {
		sec.AVProduct = "XProtect (macOS)"
		sec.AVEnabled = true
		sec.AVUpToDate = true
	}

	// macOS software update — simple count
	updates := runCmd("softwareupdate", "--list")
	if strings.Contains(updates, "No new software available") {
		sec.WUPendingCount = 0
		sec.WUCriticalCount = 0
	} else {
		count := strings.Count(updates, "* Label")
		if count == 0 {
			count = strings.Count(updates, "Recommended: YES")
		}
		sec.WUPendingCount = count
	}

	return sec
}

func collectDarwinSoftware() []SoftwareItem {
	out := runCmd("/bin/sh", "-c", `ls -1 /Applications | head -200`)
	var result []SoftwareItem
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasSuffix(line, ".app") {
			name := strings.TrimSuffix(line, ".app")
			result = append(result, SoftwareItem{Name: name})
		}
	}
	if len(result) > 200 {
		result = result[:200]
	}
	return result
}
