//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// runPS runs a PowerShell snippet and returns stdout (trimmed).
func runPS(script string) string {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// runPSLines: stdout multi-line array
func runPSLines(script string) []string {
	s := runPS(script)
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(strings.TrimRight(l, "\r"))
	}
	return lines
}

func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(s, 64)
	return v
}
func parseInt(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

// ==================== STATIC INVENTORY ====================

func collectStaticInventory() *StaticInventory {
	inv := &StaticInventory{}
	// Manufacturer + Model from Win32_ComputerSystem
	cs := runPS(`Get-CimInstance Win32_ComputerSystem | Select-Object -Property Manufacturer,Model | ForEach-Object { "$($_.Manufacturer)|$($_.Model)" }`)
	if parts := strings.SplitN(cs, "|", 2); len(parts) == 2 {
		inv.Manufacturer = parts[0]
		inv.Model = parts[1]
	}

	// Serial from BIOS
	inv.SerialNumber = runPS(`(Get-CimInstance Win32_BIOS).SerialNumber`)

	// CPU
	inv.CPU = runPS(`(Get-CimInstance Win32_Processor | Select-Object -First 1).Name`)

	// RAM total in GB
	ramBytes := runPS(`(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory`)
	if v, err := strconv.ParseFloat(ramBytes, 64); err == nil {
		inv.RAMGb = v / (1024 * 1024 * 1024)
		// Round to nearest GB
		inv.RAMGb = float64(int(inv.RAMGb + 0.5))
	}

	// Total storage (sum of fixed disks)
	storageOut := runPS(`(Get-CimInstance Win32_DiskDrive | Where-Object MediaType -like '*fixed*' | Measure-Object -Property Size -Sum).Sum`)
	if v, err := strconv.ParseFloat(storageOut, 64); err == nil {
		inv.StorageGb = v / (1024 * 1024 * 1024)
		inv.StorageGb = float64(int(inv.StorageGb + 0.5))
	}

	// OS
	osInfo := runPS(`$o = Get-CimInstance Win32_OperatingSystem; "$($o.Caption) $($o.Version)"`)
	inv.OS = strings.TrimSpace(osInfo)
	return inv
}

// ==================== HEARTBEAT (Windows) ====================

func collectHeartbeat() *HeartbeatPayload {
	hb := &HeartbeatPayload{IPInternal: getPrimaryIP()}
	// Uptime + last boot
	bootStr := runPS(`(Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'`)
	if bootStr != "" {
		hb.LastBoot = bootStr
		if t, err := time.Parse("2006-01-02T15:04:05Z", bootStr); err == nil {
			hb.UptimeSeconds = int64(time.Since(t).Seconds())
		}
	}

	// Logged-in user
	hb.LoggedInUser = runPS(`(Get-CimInstance Win32_ComputerSystem).UserName`)
	if hb.LoggedInUser == "" {
		hb.LoggedInUser = runPS(`whoami`)
	}
	// Strip DOMAIN\ prefix
	if idx := strings.Index(hb.LoggedInUser, "\\"); idx >= 0 {
		hb.LoggedInUser = hb.LoggedInUser[idx+1:]
	}

	// CPU usage (snapshot)
	cpuStr := runPS(`(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`)
	hb.CPUPercent = parseFloat(cpuStr)

	// RAM
	ramInfo := runPS(`$o = Get-CimInstance Win32_OperatingSystem; "$($o.TotalVisibleMemorySize)|$($o.FreePhysicalMemory)"`)
	if parts := strings.SplitN(ramInfo, "|", 2); len(parts) == 2 {
		totalKb := parseFloat(parts[0])
		freeKb := parseFloat(parts[1])
		if totalKb > 0 {
			hb.RAMTotalGb = totalKb / (1024 * 1024)
			hb.RAMUsedGb = (totalKb - freeKb) / (1024 * 1024)
			hb.RAMPercent = ((totalKb - freeKb) / totalKb) * 100
		}
	}

	// Disk C:
	diskInfo := runPS(`$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; "$($d.Size)|$($d.FreeSpace)"`)
	if parts := strings.SplitN(diskInfo, "|", 2); len(parts) == 2 {
		total := parseFloat(parts[0])
		free := parseFloat(parts[1])
		if total > 0 {
			hb.DiskCTotalGb = total / (1024 * 1024 * 1024)
			hb.DiskCFreeGb = free / (1024 * 1024 * 1024)
			hb.DiskCPercent = ((total - free) / total) * 100
		}
	}

	// Security
	hb.Security = collectWindowsSecurity()

	// Software inventory
	hb.Software = collectWindowsSoftware()
	return hb
}

// ==================== SECURITY ====================

func collectWindowsSecurity() *SecurityStatus {
	sec := &SecurityStatus{}

	// BitLocker (C: drive)
	blStatus := runPS(`try { (Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop).VolumeStatus } catch { 'NotAvailable' }`)
	sec.BitlockerStatus = blStatus
	sec.BitlockerEnabled = (blStatus == "FullyEncrypted" || blStatus == "EncryptionInProgress")

	// Windows Defender / AV via Get-MpComputerStatus
	avInfo := runPS(`try {
		$m = Get-MpComputerStatus -ErrorAction Stop
		$age = (Get-Date) - $m.AntivirusSignatureLastUpdated
		"$($m.AMServiceEnabled)|$($m.AntispywareSignatureLastUpdated.ToString('yyyy-MM-dd'))|$([int]$age.TotalDays)"
	} catch { 'unknown' }`)
	if parts := strings.SplitN(avInfo, "|", 3); len(parts) == 3 {
		sec.AVProduct = "Windows Defender"
		sec.AVEnabled = strings.EqualFold(parts[0], "True")
		ageDays := parseInt(parts[2])
		sec.AVSignatureAgeDays = ageDays
		sec.AVUpToDate = ageDays < 7
	}

	// Check for 3rd-party AV (SecurityCenter)
	thirdParty := runPS(`Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -notlike '*Defender*' } | Select-Object -First 1 -ExpandProperty displayName`)
	if thirdParty != "" {
		sec.AVProduct = thirdParty
		sec.AVEnabled = true
	}

	// Windows Update info
	wuInfo := runPS(`try {
		$session = New-Object -ComObject Microsoft.Update.Session
		$searcher = $session.CreateUpdateSearcher()
		$pending = $searcher.Search("IsInstalled=0 and Type='Software'").Updates.Count
		$critical = $searcher.Search("IsInstalled=0 and Type='Software' and AutoSelectOnWebSites=1").Updates.Count
		"$pending|$critical"
	} catch { '0|0' }`)
	if parts := strings.SplitN(wuInfo, "|", 2); len(parts) == 2 {
		sec.WUPendingCount = parseInt(parts[0])
		sec.WUCriticalCount = parseInt(parts[1])
	}
	sec.WULastSearch = runPS(`(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate.ToString('yyyy-MM-ddTHH:mm:ssZ') 2>$null`)
	sec.WULastInstall = runPS(`(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate.ToString('yyyy-MM-ddTHH:mm:ssZ') 2>$null`)

	// TPM
	tpmInfo := runPS(`$tpm = Get-Tpm -ErrorAction SilentlyContinue; if ($tpm) { "$($tpm.TpmPresent)|$($tpm.TpmReady)" } else { 'False|False' }`)
	if parts := strings.SplitN(tpmInfo, "|", 2); len(parts) == 2 {
		sec.TPMPresent = strings.EqualFold(parts[0], "True")
		sec.TPMReady = strings.EqualFold(parts[1], "True")
	}

	// Secure Boot
	sb := runPS(`Confirm-SecureBootUEFI -ErrorAction SilentlyContinue`)
	sec.SecureBoot = strings.EqualFold(sb, "True")

	// Firewall profiles
	fwInfo := runPS(`Get-NetFirewallProfile | Select-Object Name,Enabled | ForEach-Object { "$($_.Name):$($_.Enabled)" }`)
	for _, line := range strings.Split(fwInfo, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(line, "Domain:") {
			sec.FirewallDomain = strings.Contains(line, "True")
		} else if strings.HasPrefix(line, "Private:") {
			sec.FirewallPrivate = strings.Contains(line, "True")
		} else if strings.HasPrefix(line, "Public:") {
			sec.FirewallPublic = strings.Contains(line, "True")
		}
	}

	return sec
}

// ==================== SOFTWARE ====================

func collectWindowsSoftware() []SoftwareItem {
	// Read from registry uninstall keys (both 64-bit and 32-bit views).
	// Skip system components and updates (KBxxxxxxx).
	ps := `
$keys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$items = foreach ($k in $keys) {
    Get-ItemProperty $k -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and -not $_.SystemComponent -and $_.DisplayName -notlike 'KB*' -and $_.DisplayName -notmatch '^Update for' } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}
$items | Sort-Object DisplayName -Unique | ForEach-Object {
    "$($_.DisplayName)||$($_.DisplayVersion)||$($_.Publisher)||$($_.InstallDate)"
}
`
	out := runPS(ps)
	if out == "" {
		return nil
	}
	var result []SoftwareItem
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		parts := strings.Split(line, "||")
		if len(parts) < 1 || parts[0] == "" {
			continue
		}
		item := SoftwareItem{Name: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			item.Version = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			item.Publisher = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 && len(parts[3]) == 8 {
			// YYYYMMDD -> YYYY-MM-DD
			d := strings.TrimSpace(parts[3])
			if _, err := strconv.Atoi(d); err == nil {
				item.InstallDate = fmt.Sprintf("%s-%s-%s", d[0:4], d[4:6], d[6:8])
			}
		}
		result = append(result, item)
	}
	// Cap at 200 to keep payload reasonable
	if len(result) > 200 {
		result = result[:200]
	}
	return result
}

// Ensure runtime is referenced (avoid unused import on cross-compile)
var _ = runtime.GOOS
