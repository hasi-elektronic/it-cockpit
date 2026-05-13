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

	// Disk C: (legacy, hep doldurulur)
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

	// v0.5.0: Multi-disk (alle lokalen Laufwerke)
	hb.Disks = collectDisks()

	// v0.5.0: Top processes (RAM nach Verbrauch)
	hb.TopProcesses = collectTopProcesses()

	// v0.5.0: Browser-Versionen
	hb.Browsers = collectBrowsers()

	// v0.5.0: CPU Temperatur
	hb.CPUTempC = collectCPUTemp()

	// v0.5.0: Battery wear
	hb.BatteryWearPct, hb.BatteryHealth = collectBattery()

	// v0.5.0: Boot time (Sekunden)
	hb.BootTimeSec = collectBootTime()

	// v0.5.0: Outdated software count (winget)
	hb.OutdatedSwCount = collectOutdatedSoftware()

	// Security
	hb.Security = collectWindowsSecurity()

	// Software inventory
	hb.Software = collectWindowsSoftware()
	return hb
}

// ==================== v0.5.0 NEW COLLECTORS ====================

func collectDisks() []DiskInfo {
	// Win32_LogicalDisk: DriveType 3 = lokal, 2 = entfernbar (USB)
	// Get-PhysicalDisk: HealthStatus, MediaType, BusType -> nur wenn lokal
	raw := runPS(`
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3 OR DriveType=2" | ForEach-Object {
    $vol = $_
    $total = [math]::Round($vol.Size / 1GB, 2)
    $free  = [math]::Round($vol.FreeSpace / 1GB, 2)
    $pct = if ($vol.Size -gt 0) { [math]::Round((($vol.Size - $vol.FreeSpace) / $vol.Size) * 100, 1) } else { 0 }
    $type = if ($vol.DriveType -eq 2) { 'USB' } else { 'Local' }
    "$($vol.DeviceID)|$($vol.VolumeName)|$($vol.FileSystem)|$total|$free|$pct|$type"
}`)
	var disks []DiskInfo
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 7 {
			continue
		}
		d := DiskInfo{
			Mount:      parts[0],
			Label:      parts[1],
			FileSystem: parts[2],
			TotalGb:    parseFloat(parts[3]),
			FreeGb:     parseFloat(parts[4]),
			Percent:    parseFloat(parts[5]),
			Type:       parts[6],
		}
		disks = append(disks, d)
	}

	// SMART health pro PhysicalDisk (mapped per mount letter via partition)
	smartMap := runPS(`
try {
  Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
    $p = $_
    $partitions = Get-Partition -DiskNumber $p.DeviceId -ErrorAction SilentlyContinue
    $letters = ($partitions | Where-Object { $_.DriveLetter } | ForEach-Object { $_.DriveLetter + ':' }) -join ','
    $mediaType = if ($p.MediaType) { $p.MediaType } else { 'Unknown' }
    "$letters|$($p.HealthStatus)|$mediaType"
  }
} catch { '' }`)
	for _, line := range strings.Split(smartMap, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		letters := parts[0]
		health := parts[1]
		mediaType := parts[2]
		for _, letter := range strings.Split(letters, ",") {
			letter = strings.TrimSpace(letter)
			for i := range disks {
				if disks[i].Mount == letter {
					disks[i].SMARTHealth = health
					if disks[i].Type == "Local" && mediaType != "" && mediaType != "Unspecified" {
						disks[i].Type = mediaType // SSD, HDD, NVMe
					}
				}
			}
		}
	}
	return disks
}

func collectTopProcesses() []ProcessInfo {
	// Top 10 nach RAM (Working Set)
	raw := runPS(`Get-Process | Sort-Object WS -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name)|$($_.Id)|$($_.WS)" }`)
	var procs []ProcessInfo
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		procs = append(procs, ProcessInfo{
			Name:  parts[0],
			PID:   parseInt(parts[1]),
			RAMMb: parseFloat(parts[2]) / (1024 * 1024),
		})
	}
	return procs
}

func collectBrowsers() []BrowserInfo {
	// Chrome, Edge, Firefox Versionen aus Registry / Executable
	var browsers []BrowserInfo

	chrome := runPS(`(Get-Item -Path 'HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463c-AFF1-A69D9E530F96}' -ErrorAction SilentlyContinue).GetValue('pv')`)
	if chrome == "" {
		chrome = runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Google\Chrome\BLBeacon' -ErrorAction SilentlyContinue).version`)
	}
	if chrome != "" {
		// Latest stable as of 2026 is around 130+. Mark anything below 120 as outdated.
		outdated := isVersionOlderThan(chrome, 120)
		browsers = append(browsers, BrowserInfo{Name: "Google Chrome", Version: chrome, Outdated: outdated})
	}

	edge := runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -ErrorAction SilentlyContinue).pv`)
	if edge == "" {
		edge = runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Edge\BLBeacon' -ErrorAction SilentlyContinue).version`)
	}
	if edge != "" {
		outdated := isVersionOlderThan(edge, 120)
		browsers = append(browsers, BrowserInfo{Name: "Microsoft Edge", Version: edge, Outdated: outdated})
	}

	firefox := runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox' -ErrorAction SilentlyContinue).CurrentVersion`)
	if firefox != "" {
		outdated := isVersionOlderThan(firefox, 115)
		browsers = append(browsers, BrowserInfo{Name: "Mozilla Firefox", Version: firefox, Outdated: outdated})
	}

	return browsers
}

func isVersionOlderThan(ver string, minMajor int) bool {
	parts := strings.Split(ver, ".")
	if len(parts) == 0 {
		return false
	}
	major := parseInt(parts[0])
	if major == 0 {
		return false
	}
	return major < minMajor
}

func collectCPUTemp() float64 {
	// MSAcpi_ThermalZoneTemperature gibt in Zehntel-Kelvin
	tempRaw := runPS(`try { (Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1).CurrentTemperature } catch { '' }`)
	if tempRaw == "" {
		return 0
	}
	tenthsKelvin := parseFloat(tempRaw)
	if tenthsKelvin <= 0 {
		return 0
	}
	return (tenthsKelvin / 10.0) - 273.15
}

func collectBattery() (float64, string) {
	// Get-CimInstance Win32_Battery: nur bei Laptops vorhanden
	batt := runPS(`try {
  $b = Get-CimInstance Win32_Battery -ErrorAction Stop | Select-Object -First 1
  if ($b) {
    $design = (Get-CimInstance -Namespace root/WMI -ClassName BatteryStaticData -ErrorAction SilentlyContinue | Select-Object -First 1).DesignedCapacity
    $full = (Get-CimInstance -Namespace root/WMI -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1).FullChargedCapacity
    if ($design -gt 0 -and $full -gt 0) {
      $wear = [math]::Round((($design - $full) / $design) * 100, 1)
      "$wear|$design|$full"
    } else { '' }
  } else { '' }
} catch { '' }`)
	if batt == "" || !strings.Contains(batt, "|") {
		return 0, ""
	}
	parts := strings.Split(batt, "|")
	wear := parseFloat(parts[0])
	health := "Gut"
	if wear > 30 {
		health = "Schlecht"
	} else if wear > 15 {
		health = "OK"
	}
	return wear, health
}

func collectBootTime() int {
	// Letzte Bootzeit in Sekunden (Win32_PerfFormattedData_PerfOS_System -> SystemUpTime is uptime, not boot duration)
	// Alternativ: EventLog 12 (boot) und 6005 timestamps
	raw := runPS(`try {
  $boot = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=100; ProviderName='Microsoft-Windows-Kernel-Boot' } -MaxEvents 1 -ErrorAction Stop
  if ($boot) { [int]($boot.Properties[0].Value / 1000) } else { 0 }
} catch { 0 }`)
	return parseInt(raw)
}

func collectOutdatedSoftware() int {
	// winget upgrade --include-unknown returns lines of pending updates
	raw := runPS(`try {
  $count = (winget upgrade --include-unknown 2>$null | Where-Object { $_ -match '^\S+\s+\S+\s+\d' }).Count
  $count
} catch { 0 }`)
	return parseInt(raw)
}

// ==================== SECURITY ====================

func collectWindowsSecurity() *SecurityStatus {
	sec := &SecurityStatus{}

	// BitLocker (C: drive)
	blStatus := runPS(`try { (Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop).VolumeStatus } catch { 'NotAvailable' }`)
	sec.BitlockerStatus = blStatus
	sec.BitlockerEnabled = (blStatus == "FullyEncrypted" || blStatus == "EncryptionInProgress")

	// ==================== ANTIVIRUS DETECTION (all vendors) ====================
	//
	// SecurityCenter2 namespace listet ALLE registrierten AV-Produkte mit productState.
	// productState ist ein 32-bit Bitfield:
	//   - Byte 2 (Bits 16-23): Produkt-Typ (0x10=AV, 0x40=AS, 0x01=FW)
	//   - Byte 1 (Bits 8-15):  Status (0x10=On/aktiv, 0x00=Off/inaktiv, 0x01=Snoozed)
	//   - Byte 0 (Bits 0-7):   Signaturen (0x00=aktuell, 0x10=veraltet/expired)
	//
	// Wir nehmen das erste aktive Produkt (Priorität: 3rd-party > Defender),
	// damit z.B. G Data, Bitdefender, Kaspersky korrekt erkannt werden.

	avListRaw := runPS(`try {
		Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |
		ForEach-Object { "$($_.displayName)|$($_.productState)" }
	} catch { '' }`)

	type avEntry struct {
		Name    string
		State   int64
		IsOn    bool
		IsCurrent bool
		IsDefender bool
	}
	var avEntries []avEntry
	for _, line := range strings.Split(avListRaw, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || !strings.Contains(line, "|") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		name := strings.TrimSpace(parts[0])
		stateStr := strings.TrimSpace(parts[1])
		state, _ := strconv.ParseInt(stateStr, 10, 64)
		// Bit 12 (0x1000) = enabled/On
		isOn := (state & 0x1000) != 0
		// Bit 4 (0x10) on signature byte = outdated; 0 = current
		isCurrent := (state & 0x10) == 0
		isDefender := strings.Contains(strings.ToLower(name), "defender") ||
			strings.Contains(strings.ToLower(name), "microsoft")
		avEntries = append(avEntries, avEntry{name, state, isOn, isCurrent, isDefender})
	}

	// Wähle das beste AV-Produkt: aktiv vor inaktiv, Suite-Vendor vor komplementär, 3rd-party vor Defender
	// Bekannte vollwertige Security-Suiten: bevorzugen über reine Anti-Malware-Scanner wie Malwarebytes
	isSuite := func(name string) bool {
		n := strings.ToLower(name)
		suites := []string{"g data", "g-data", "gdata", "bitdefender", "kaspersky", "eset", "mcafee",
			"sophos", "norton", "avira", "avast", "avg", "f-secure", "fsecure", "trend micro", "trendmicro",
			"emsisoft", "panda", "comodo", "k7", "quick heal", "webroot"}
		for _, s := range suites {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}

	bestIdx := -1
	for i, a := range avEntries {
		if bestIdx == -1 {
			bestIdx = i
			continue
		}
		best := avEntries[bestIdx]
		// Bewertung: aktiv (8) + Suite (4) + !Defender (2) + current (1)
		bestScore := 0
		if best.IsOn { bestScore += 8 }
		if isSuite(best.Name) { bestScore += 4 }
		if !best.IsDefender { bestScore += 2 }
		if best.IsCurrent { bestScore += 1 }
		curScore := 0
		if a.IsOn { curScore += 8 }
		if isSuite(a.Name) { curScore += 4 }
		if !a.IsDefender { curScore += 2 }
		if a.IsCurrent { curScore += 1 }
		if curScore > bestScore {
			bestIdx = i
		}
	}

	if bestIdx >= 0 {
		best := avEntries[bestIdx]
		sec.AVProduct = best.Name
		sec.AVEnabled = best.IsOn
		// Wenn das beste AV Defender ist, sind die genauen Signatur-Daten via Get-MpComputerStatus präziser
		if best.IsDefender {
			avInfo := runPS(`try {
				$m = Get-MpComputerStatus -ErrorAction Stop
				$age = (Get-Date) - $m.AntivirusSignatureLastUpdated
				"$($m.AMServiceEnabled)|$([int]$age.TotalDays)"
			} catch { '' }`)
			if parts := strings.SplitN(avInfo, "|", 2); len(parts) == 2 {
				sec.AVEnabled = strings.EqualFold(parts[0], "True")
				ageDays := parseInt(parts[1])
				sec.AVSignatureAgeDays = ageDays
				sec.AVUpToDate = ageDays < 7
			}
		} else {
			// 3rd-party AV: Signatur-Status aus productState ableiten
			sec.AVUpToDate = best.IsCurrent
			// SignatureAgeDays: 0 wenn current, sonst 30 (Annahme, da exakte Daten vendor-spezifisch)
			if best.IsCurrent {
				sec.AVSignatureAgeDays = 0
			} else {
				sec.AVSignatureAgeDays = 30
			}
		}
	} else {
		// Fallback: Get-MpComputerStatus direkt (alte Windows ohne SecurityCenter2)
		avInfo := runPS(`try {
			$m = Get-MpComputerStatus -ErrorAction Stop
			$age = (Get-Date) - $m.AntivirusSignatureLastUpdated
			"$($m.AMServiceEnabled)|$([int]$age.TotalDays)"
		} catch { '' }`)
		if parts := strings.SplitN(avInfo, "|", 2); len(parts) == 2 {
			sec.AVProduct = "Windows Defender"
			sec.AVEnabled = strings.EqualFold(parts[0], "True")
			ageDays := parseInt(parts[1])
			sec.AVSignatureAgeDays = ageDays
			sec.AVUpToDate = ageDays < 7
		}
	}

	// v0.5.2: ALLE AV-Produkte als Liste (nicht nur "primary")
	for _, a := range avEntries {
		sec.AVProducts = append(sec.AVProducts, AVProductInfo{
			Name:         a.Name,
			Enabled:      a.IsOn,
			UpToDate:     a.IsCurrent,
			IsDefender:   a.IsDefender,
			ProductState: a.State,
		})
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

	// ============== v0.5.0 NEW SECURITY METRICS ==============

	// Defender Tamper Protection (verhindert dass Malware Defender deaktiviert)
	tamper := runPS(`try { (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch { '' }`)
	sec.DefenderTamperOn = strings.EqualFold(tamper, "True")

	// UAC enabled (EnableLUA in Registry)
	uac := runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA`)
	sec.UACEnabled = uac == "1"

	// RDP enabled (fDenyTSConnections == 0 = aktiv)
	rdp := runPS(`(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections`)
	sec.RDPEnabled = rdp == "0"

	// Auto-login enabled
	autoLogin := runPS(`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).AutoAdminLogon`)
	sec.AutoLoginEnabled = autoLogin == "1"

	// Pending reboot (4 yöntem)
	rebootReason := runPS(`
$reasons = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'WindowsUpdate' }
$pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($pfro) { $reasons += 'FileRename' }
try {
  $ccm = Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
  if ($ccm.RebootPending) { $reasons += 'SCCM' }
} catch {}
$reasons -join ','`)
	sec.PendingReboot = rebootReason != ""
	sec.PendingRebootReason = rebootReason

	// Failed logons (last 24h) — Event ID 4625
	failedLogons := runPS(`try {
  $since = (Get-Date).AddDays(-1)
  $count = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$since } -ErrorAction Stop -MaxEvents 500 | Measure-Object).Count
  $count
} catch { 0 }`)
	sec.FailedLogons24h = parseInt(failedLogons)

	// Local administrators
	localAdmins := runPS(`try {
  $g = Get-LocalGroupMember -Group 'Administratoren' -ErrorAction Stop
  if (-not $g) { $g = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
  if ($g) { ($g | Measure-Object).Count } else { 0 }
} catch {
  try { (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Measure-Object).Count } catch { 0 }
}`)
	sec.LocalAdminCount = parseInt(localAdmins)

	// Open listening ports
	openPorts := runPS(`try {
  $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique
  $tcp -join ','
} catch { '' }`)
	sec.OpenPortsList = openPorts
	if openPorts != "" {
		sec.OpenPortsCount = len(strings.Split(openPorts, ","))
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
