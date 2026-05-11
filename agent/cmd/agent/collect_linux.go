//go:build linux

package main

import (
	"os"
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

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func collectStaticInventory() *StaticInventory {
	inv := &StaticInventory{}
	inv.Manufacturer = readFile("/sys/devices/virtual/dmi/id/sys_vendor")
	inv.Model = readFile("/sys/devices/virtual/dmi/id/product_name")
	inv.SerialNumber = readFile("/sys/devices/virtual/dmi/id/product_serial")

	// CPU model
	cpu := runCmd("/bin/sh", "-c", "grep -m1 'model name' /proc/cpuinfo | cut -d':' -f2")
	inv.CPU = strings.TrimSpace(cpu)

	// RAM
	meminfo := readFile("/proc/meminfo")
	for _, line := range strings.Split(meminfo, "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, _ := strconv.ParseFloat(parts[1], 64)
				inv.RAMGb = float64(int((kb / (1024 * 1024)) + 0.5))
			}
			break
		}
	}

	// Storage (root)
	dfOut := runCmd("/bin/sh", "-c", "df -k / | tail -1 | awk '{print $2}'")
	if v, err := strconv.ParseFloat(dfOut, 64); err == nil {
		inv.StorageGb = float64(int((v / (1024 * 1024)) + 0.5))
	}

	// OS
	osRelease := readFile("/etc/os-release")
	var prettyName string
	for _, line := range strings.Split(osRelease, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			break
		}
	}
	if prettyName == "" {
		prettyName = "Linux"
	}
	kernel := runCmd("uname", "-r")
	inv.OS = prettyName + " (kernel " + kernel + ")"
	return inv
}

func collectHeartbeat() *HeartbeatPayload {
	hb := &HeartbeatPayload{IPInternal: getPrimaryIP()}
	// Logged-in user
	user := runCmd("/bin/sh", "-c", "who | head -1 | awk '{print $1}'")
	if user == "" {
		user = os.Getenv("USER")
	}
	hb.LoggedInUser = user

	// Uptime
	upt := readFile("/proc/uptime")
	if parts := strings.Fields(upt); len(parts) > 0 {
		if sec, err := strconv.ParseFloat(parts[0], 64); err == nil {
			hb.UptimeSeconds = int64(sec)
			bootTime := time.Now().Add(-time.Duration(sec) * time.Second).UTC()
			hb.LastBoot = bootTime.Format("2006-01-02T15:04:05Z")
		}
	}

	// CPU usage (1-second sample via /proc/stat)
	hb.CPUPercent = readCPUPercent()

	// RAM
	meminfo := readFile("/proc/meminfo")
	var memTotal, memAvailable float64
	for _, line := range strings.Split(meminfo, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(parts[1], 64)
		switch parts[0] {
		case "MemTotal:":
			memTotal = v
		case "MemAvailable:":
			memAvailable = v
		}
	}
	if memTotal > 0 {
		hb.RAMTotalGb = memTotal / (1024 * 1024)
		hb.RAMUsedGb = (memTotal - memAvailable) / (1024 * 1024)
		hb.RAMPercent = ((memTotal - memAvailable) / memTotal) * 100
	}

	// Disk root
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

	hb.Security = collectLinuxSecurity()
	hb.Software = collectLinuxSoftware()
	return hb
}

func readCPUPercent() float64 {
	read := func() (idle, total float64) {
		data := readFile("/proc/stat")
		if data == "" {
			return 0, 0
		}
		line := strings.SplitN(data, "\n", 2)[0]
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			return 0, 0
		}
		for i := 1; i < len(fields); i++ {
			v, _ := strconv.ParseFloat(fields[i], 64)
			total += v
			if i == 4 {
				idle = v
			}
		}
		return
	}
	i1, t1 := read()
	time.Sleep(500 * time.Millisecond)
	i2, t2 := read()
	dt := t2 - t1
	di := i2 - i1
	if dt <= 0 {
		return 0
	}
	return ((dt - di) / dt) * 100
}

func collectLinuxSecurity() *SecurityStatus {
	sec := &SecurityStatus{}

	// LUKS check (rough)
	if strings.Contains(runCmd("lsblk", "-o", "NAME,FSTYPE"), "crypto_LUKS") {
		sec.BitlockerEnabled = true
		sec.BitlockerStatus = "LUKS Active"
	}

	// UFW
	if out := runCmd("ufw", "status"); strings.Contains(out, "Status: active") {
		sec.FirewallDomain = true
		sec.FirewallPrivate = true
		sec.FirewallPublic = true
	} else if out := runCmd("systemctl", "is-active", "firewalld"); out == "active" {
		sec.FirewallDomain = true
		sec.FirewallPrivate = true
		sec.FirewallPublic = true
	}

	// Secure Boot
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		sb := runCmd("/bin/sh", "-c", "mokutil --sb-state 2>/dev/null")
		sec.SecureBoot = strings.Contains(sb, "SecureBoot enabled")
	}

	// ClamAV check (optional)
	if runCmd("which", "clamscan") != "" {
		sec.AVProduct = "ClamAV"
		sec.AVEnabled = true
		sec.AVUpToDate = true
	}

	// Pending updates (apt)
	if runCmd("which", "apt") != "" {
		out := runCmd("/bin/sh", "-c", "apt list --upgradeable 2>/dev/null | wc -l")
		if v, err := strconv.Atoi(out); err == nil && v > 0 {
			sec.WUPendingCount = v - 1 // subtract header
		}
	}

	return sec
}

func collectLinuxSoftware() []SoftwareItem {
	var result []SoftwareItem
	// dpkg-based
	if runCmd("which", "dpkg-query") != "" {
		out := runCmd("/bin/sh", "-c", `dpkg-query -W -f='${Package}||${Version}||${Maintainer}\n' 2>/dev/null | head -200`)
		for _, line := range strings.Split(out, "\n") {
			parts := strings.Split(line, "||")
			if len(parts) >= 1 && parts[0] != "" {
				item := SoftwareItem{Name: parts[0]}
				if len(parts) > 1 {
					item.Version = parts[1]
				}
				if len(parts) > 2 {
					item.Publisher = parts[2]
				}
				result = append(result, item)
			}
		}
	} else if runCmd("which", "rpm") != "" {
		out := runCmd("/bin/sh", "-c", `rpm -qa --queryformat '%{NAME}||%{VERSION}||%{VENDOR}\n' 2>/dev/null | head -200`)
		for _, line := range strings.Split(out, "\n") {
			parts := strings.Split(line, "||")
			if len(parts) >= 1 && parts[0] != "" {
				item := SoftwareItem{Name: parts[0]}
				if len(parts) > 1 {
					item.Version = parts[1]
				}
				if len(parts) > 2 {
					item.Publisher = parts[2]
				}
				result = append(result, item)
			}
		}
	}
	if len(result) > 200 {
		result = result[:200]
	}
	return result
}
