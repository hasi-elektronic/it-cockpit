package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ==================== Types ====================

type Command struct {
	ID      int             `json:"id"`
	Type    string          `json:"type"`
	Args    json.RawMessage `json:"args"`
	Timeout int             `json:"timeout"`
}

type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

type CommandResult struct {
	Status       string `json:"status"`       // "done" | "error"
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	ExitCode     int    `json:"exit_code"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ==================== Poll ====================

// pollCommands fetches pending commands from the server, executes each, posts result.
// Called from main loop every iteration (after heartbeat).
func pollCommands(cfg *Config, state *State) {
	body, status, err := getJSON(cfg.APIURL+"/agent/commands", map[string]string{
		"X-Agent-Token": state.AgentToken,
	})
	if err != nil {
		log.Printf("Command poll failed: %v", err)
		return
	}
	if status != 200 {
		log.Printf("Command poll bad status %d: %s", status, string(body))
		return
	}
	var resp CommandsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		log.Printf("Command poll parse: %v", err)
		return
	}
	if len(resp.Commands) == 0 {
		return
	}
	log.Printf("Received %d command(s)", len(resp.Commands))

	for _, cmd := range resp.Commands {
		result := executeCommand(cmd)
		if err := postCommandResult(cfg, state, cmd.ID, result); err != nil {
			log.Printf("Command #%d result post failed: %v", cmd.ID, err)
		} else {
			log.Printf("Command #%d (%s) -> %s", cmd.ID, cmd.Type, result.Status)
		}
	}
}

func postCommandResult(cfg *Config, state *State, cmdID int, result CommandResult) error {
	url := fmt.Sprintf("%s/agent/commands/%d/result", cfg.APIURL, cmdID)
	body, status, err := postJSON(url, result, map[string]string{
		"X-Agent-Token": state.AgentToken,
	})
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("status %d: %s", status, string(body))
	}
	return nil
}

// ==================== Execute ====================

func executeCommand(cmd Command) CommandResult {
	timeout := cmd.Timeout
	if timeout <= 0 || timeout > 600 {
		timeout = 120
	}

	switch cmd.Type {
	case "ping":
		return CommandResult{Status: "done", Stdout: fmt.Sprintf("pong from %s %s/%s", getHostname(), runtime.GOOS, runtime.GOARCH), ExitCode: 0}

	case "msg":
		var args struct{ Message string `json:"message"` }
		if err := json.Unmarshal(cmd.Args, &args); err != nil {
			return errResult("invalid args: " + err.Error())
		}
		return doShowMessage(args.Message)

	case "lock":
		return doLockScreen()

	case "reboot":
		var args struct{ DelaySeconds int `json:"delay_seconds"` }
		_ = json.Unmarshal(cmd.Args, &args)
		if args.DelaySeconds < 0 {
			args.DelaySeconds = 60
		}
		return doReboot(args.DelaySeconds)

	case "ps":
		var args struct{ Script string `json:"script"` }
		if err := json.Unmarshal(cmd.Args, &args); err != nil {
			return errResult("invalid args: " + err.Error())
		}
		return runShell("powershell", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", args.Script}, timeout)

	case "cmd":
		var args struct{ Command string `json:"command"` }
		if err := json.Unmarshal(cmd.Args, &args); err != nil {
			return errResult("invalid args: " + err.Error())
		}
		if runtime.GOOS == "windows" {
			return runShell("cmd", []string{"/c", args.Command}, timeout)
		}
		return runShell("sh", []string{"-c", args.Command}, timeout)

	default:
		return errResult("unknown command type: " + cmd.Type)
	}
}

func errResult(msg string) CommandResult {
	return CommandResult{Status: "error", ErrorMessage: msg, ExitCode: -1}
}

func runShell(name string, args []string, timeoutSeconds int) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	hideConsoleWindow(cmd)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	status := "done"
	errMsg := ""
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			status = "error"
			errMsg = fmt.Sprintf("timeout after %ds", timeoutSeconds)
		} else if exitCode != 0 {
			// non-zero exit is still "done" — admin can read exit code
		} else {
			status = "error"
			errMsg = err.Error()
		}
	}
	return CommandResult{
		Status:       status,
		Stdout:       stdout.String(),
		Stderr:       stderr.String(),
		ExitCode:     exitCode,
		ErrorMessage: errMsg,
	}
}

// ==================== Platform-specific actions ====================

func doShowMessage(message string) CommandResult {
	if runtime.GOOS == "windows" {
		// msg.exe to logged-in user (works as SYSTEM)
		safe := strings.ReplaceAll(message, "\"", "'")
		// Use msg.exe * /TIME:60 (broadcast to all sessions on this machine)
		return runShell("msg", []string{"*", "/TIME:60", safe}, 10)
	}
	if runtime.GOOS == "darwin" {
		safe := strings.ReplaceAll(message, "\"", "\\\"")
		script := fmt.Sprintf(`display notification "%s" with title "Hasi IT-Cockpit"`, safe)
		return runShell("osascript", []string{"-e", script}, 10)
	}
	// Linux: try notify-send (assumes user session has it)
	return runShell("notify-send", []string{"Hasi IT-Cockpit", message}, 10)
}

func doLockScreen() CommandResult {
	if runtime.GOOS == "windows" {
		return runShell("rundll32.exe", []string{"user32.dll,LockWorkStation"}, 10)
	}
	if runtime.GOOS == "darwin" {
		return runShell("pmset", []string{"displaysleepnow"}, 10)
	}
	// Linux best effort
	return runShell("loginctl", []string{"lock-session"}, 10)
}

func doReboot(delaySeconds int) CommandResult {
	if runtime.GOOS == "windows" {
		// shutdown /r /t <seconds> /c "<message>"
		return runShell("shutdown", []string{"/r", "/t", fmt.Sprintf("%d", delaySeconds), "/c", "Hasi IT-Cockpit: Neustart geplant"}, 10)
	}
	if runtime.GOOS == "darwin" {
		// requires SYSTEM/root; best effort
		args := []string{"-r", fmt.Sprintf("+%d", delaySeconds/60)}
		return runShell("shutdown", args, 10)
	}
	args := []string{"-r", fmt.Sprintf("+%d", delaySeconds/60)}
	return runShell("shutdown", args, 10)
}
