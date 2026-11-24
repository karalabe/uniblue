// Command uniblue is a blue-team security agent for UniFi networks.
// It pulls live topology from a local UniFi controller, gently fingerprints
// LAN hosts, runs declarative community-submitted checks, and scores risk by
// VLAN and WAN blast radius.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/notify"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "uniblue: %v\n", err)
		os.Exit(1)
	}
}

// run dispatches CLI subcommands so main remains tiny and easily testable.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing subcommand")
	}

	// Cancel gracefully on SIGINT/SIGTERM so active scans finish or abort cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "watch":
		return runWatch(ctx, args[1:], stdout, stderr)
	case "inventory":
		return runInventory(ctx, args[1:], stdout, stderr)
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// printUsage writes top-level command help to w.
func printUsage(w io.Writer) {
	fmt.Fprintln(w, `UniBlue - Blue-Team Security Agent for UniFi Networks

Usage:
  uniblue <command> [flags]

Commands:
  scan        Run a single UniFi + LAN security scan and print prioritized findings
  watch       Continuously scan on an interval and notify only on new/escalated changes
  inventory   Fetch and display UniFi clients, devices, VLANs, and port forwards
  check       Validate or test declarative YAML checks against a single host`)
}

// runScan executes one complete UniFi sync, gentle host probe, check pass, and
// blast-radius evaluation, printing the report to stdout.
func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	jsonOut := fs.Bool("json", false, "output report as JSON")
	saveState := fs.Bool("save-state", false, "persist scan baseline to configured state.path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
	if err != nil {
		return err
	}

	snap, report, err := executeCycle(ctx, cfg, checkList)
	if err != nil {
		return err
	}

	if *saveState {
		st := risk.BuildState(snap, report, cfg.Network)
		if err := risk.SaveState(cfg.State.Path, st); err != nil {
			return err
		}
	}

	if *jsonOut {
		return writeJSON(stdout, report)
	}
	printReport(stdout, snap, report)
	return nil
}

// runWatch runs executeCycle immediately and then on cfg.Scan.Interval,
// persisting state.json and sending webhook alerts only when meaningful changes
// occur.
func runWatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
	if err != nil {
		return err
	}
	notifier, err := notify.New(cfg.Notify)
	if err != nil {
		return err
	}
	minSev, err := checks.ParseSeverity(cfg.Notify.MinSeverity)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	logger.Info("starting uniblue watch",
		"site", cfg.UniFi.Site,
		"interval", cfg.Scan.Interval,
		"checks", len(checkList),
		"state_path", cfg.State.Path,
	)

	// Run one pass immediately, then repeat on a ticker until cancelled.
	runOnce := func() {
		prev, err := risk.LoadState(cfg.State.Path)
		if err != nil {
			logger.Error("failed to load previous state", "err", err)
			return
		}

		snap, report, err := executeCycle(ctx, cfg, checkList)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("scan cycle failed", "err", err)
			return
		}

		diff := risk.ComputeDiff(prev, snap, report, cfg.Network)
		logger.Info("scan cycle complete",
			"clients", report.ClientCount,
			"findings", len(report.Findings),
			"new", len(diff.NewFindings),
			"escalated", len(diff.EscalatedFindings),
			"resolved", len(diff.ResolvedKeys),
			"new_trusted_clients", len(diff.NewTrustedClients),
			"new_port_forwards", len(diff.NewPortForwards),
		)

		if diff.HasAlerts(minSev) {
			if err := notifier.Send(ctx, snap.Site, diff); err != nil {
				logger.Error("failed to send notification", "err", err)
			}
		}

		nextState := risk.BuildState(snap, report, cfg.Network)
		if err := risk.SaveState(cfg.State.Path, nextState); err != nil {
			logger.Error("failed to save state", "err", err)
		}
	}

	runOnce()

	ticker := time.NewTicker(cfg.Scan.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("stopping uniblue watch")
			return nil
		case <-ticker.C:
			runOnce()
		}
	}
}

// runInventory connects to UniFi and prints the discovered clients, UniFi gear,
// VLANs, and port forwards without actively probing LAN hosts.
func runInventory(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	jsonOut := fs.Bool("json", false, "output inventory snapshot as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctrl, err := unifi.New(cfg.UniFi)
	if err != nil {
		return err
	}
	if err := ctrl.Login(ctx); err != nil {
		return err
	}
	snap, err := ctrl.FetchSnapshot(ctx)
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(stdout, snap)
	}
	printInventory(stdout, snap)
	return nil
}

// runCheck handles `uniblue check validate` and `uniblue check test`.
func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: uniblue check <validate|test> [flags]")
	}
	switch args[0] {
	case "validate":
		return runCheckValidate(args[1:], stdout, stderr)
	case "test":
		return runCheckTest(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown check subcommand %q (want validate or test)", args[0])
	}
}

// runCheckValidate loads and validates all built-in checks plus an optional
// local directory of community checks, failing with a non-zero exit code on any
// schema or safety violation.
func runCheckValidate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "optional directory of extra YAML checks to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	list, err := loadAllChecks(*dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Validated %d checks successfully:\n", len(list))
	for _, chk := range list {
		fmt.Fprintf(stdout, "  %-14s [%-8s] %s (%s)\n", chk.ID, chk.Severity, chk.Title, chk.Source)
	}
	return nil
}

// runCheckTest fingerprints and runs checks against a single LAN IP without
// needing UniFi credentials, making it easy to develop and verify new checks.
func runCheckTest(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", "", "target LAN IP address to test")
	dir := fs.String("dir", "", "optional directory of extra YAML checks")
	checkID := fs.String("check", "", "optional single check ID to run (e.g., UB-0003)")
	timeout := fs.Duration("timeout", 3*time.Second, "per-probe timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return errors.New("check test requires -target <ip>")
	}

	list, err := loadAllChecks(*dir)
	if err != nil {
		return err
	}
	if *checkID != "" {
		var filtered []*checks.Check
		for _, chk := range list {
			if strings.EqualFold(chk.ID, *checkID) {
				filtered = append(filtered, chk)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("check %q not found", *checkID)
		}
		list = filtered
	}

	// Build a minimal port list covering every precondition port across the
	// selected checks plus UniBlue's default ports.
	portSet := make(map[int]struct{})
	for _, p := range config.DefaultPorts {
		portSet[p] = struct{}{}
	}
	for _, chk := range list {
		for _, p := range chk.Preconditions.PortsAny {
			portSet[p] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}

	fp := probe.NewFingerprinter(ports, 1, *timeout, nil)
	profile := fp.FingerprintHost(ctx, unifi.Client{IP: *target, Name: *target})

	fmt.Fprintf(stdout, "Target: %s | Open ports: %v\n", *target, profile.OpenPorts)
	for port, banner := range profile.HTTP {
		fmt.Fprintf(stdout, "  HTTP(%d): status=%d server=%q title=%q\n", port, banner.StatusCode, banner.Server, banner.Title)
	}

	runner := checks.NewRunner(list, 1)
	findings := runner.RunHost(ctx, profile)
	if len(findings) == 0 {
		fmt.Fprintln(stdout, "No findings matched.")
		return nil
	}
	for _, f := range findings {
		fmt.Fprintf(stdout, "[%s] %s (%s) on port %d: %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Title, f.Port, f.Evidence)
	}
	return nil
}

// executeCycle runs one end-to-end UniFi snapshot, host fingerprinting pass,
// declarative check sweep, and blast-radius risk evaluation.
func executeCycle(ctx context.Context, cfg *config.Config, checkList []*checks.Check) (*unifi.Snapshot, risk.Report, error) {
	ctrl, err := unifi.New(cfg.UniFi)
	if err != nil {
		return nil, risk.Report{}, err
	}
	if err := ctrl.Login(ctx); err != nil {
		return nil, risk.Report{}, err
	}
	snap, err := ctrl.FetchSnapshot(ctx)
	if err != nil {
		return nil, risk.Report{}, err
	}

	// Union configured default ports with any specialty ports required by loaded
	// community checks (such as port 56747 for Zehnder ComfoConnect) so dropping
	// a new YAML check into checks/ works without editing config.yaml.
	scanPorts := mergePorts(cfg.Scan.Ports, checkList)

	fp := probe.NewFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet())
	profiles := fp.FingerprintAll(ctx, snap.Clients)

	runner := checks.NewRunner(checkList, cfg.Scan.Concurrency)
	rawFindings := runner.RunAll(ctx, profiles)

	report := risk.Evaluate(snap, rawFindings, cfg.Network)
	return snap, report, nil
}

// mergePorts returns the deduplicated union of basePorts and every port
// referenced in loaded check preconditions.
func mergePorts(basePorts []int, list []*checks.Check) []int {
	seen := make(map[int]struct{}, len(basePorts))
	merged := make([]int, 0, len(basePorts))
	for _, p := range basePorts {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			merged = append(merged, p)
		}
	}
	for _, chk := range list {
		for _, p := range chk.Preconditions.PortsAny {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				merged = append(merged, p)
			}
		}
	}
	return merged
}

// loadAllChecks loads the embedded built-in checks and optionally merges checks
// from an external local directory.
func loadAllChecks(extraDir string) ([]*checks.Check, error) {
	builtins, err := checks.LoadFromFS(builtinchecks.BuiltinFS)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(extraDir) == "" {
		return checks.Merge(builtins)
	}
	custom, err := checks.LoadFromDir(extraDir)
	if err != nil {
		return nil, err
	}
	return checks.Merge(builtins, custom)
}

// printReport renders a prioritized, operator-friendly summary to w.
func printReport(w io.Writer, snap *unifi.Snapshot, report risk.Report) {
	fmt.Fprintf(w, "UniBlue Scan Report | Site: %s (%s) | Clients: %d | Findings: %d\n\n",
		snap.Site, snap.ControllerType, report.ClientCount, len(report.Findings))

	if len(report.Findings) == 0 {
		fmt.Fprintln(w, "No findings detected.")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCHECK\tHOST\tIP:PORT\tVLAN\tTITLE")
	for _, f := range report.Findings {
		ipPort := f.Client.IP
		if f.Port > 0 {
			ipPort = fmt.Sprintf("%s:%d", f.Client.IP, f.Port)
		}
		vlan := f.Client.NetworkName
		if vlan == "" {
			vlan = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(f.EffectiveSeverity.String()),
			f.CheckID,
			f.Client.DisplayName(),
			ipPort,
			vlan,
			f.Title,
		)
	}
	_ = tw.Flush()

	fmt.Fprintln(w, "\nDetails:")
	for _, f := range report.Findings {
		fmt.Fprintf(w, "- [%s] %s on %s (%s)\n",
			strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Client.DisplayName(), f.Client.IP)
		fmt.Fprintf(w, "  Evidence: %s\n", f.Evidence)
		if len(f.RiskReasons) > 0 {
			fmt.Fprintf(w, "  Blast Radius: %s\n", strings.Join(f.RiskReasons, "; "))
		}
		if f.Remediation.Summary != "" {
			fmt.Fprintf(w, "  Remediation: %s\n", strings.TrimSpace(f.Remediation.Summary))
		}
	}
}

// printInventory renders the UniFi snapshot tables cleanly for `uniblue inventory`.
func printInventory(w io.Writer, snap *unifi.Snapshot) {
	fmt.Fprintf(w, "UniFi Site: %s (%s) | Clients: %d | Devices: %d | Networks: %d | Port Forwards: %d\n\n",
		snap.Site, snap.ControllerType, len(snap.Clients), len(snap.Devices), len(snap.Networks), len(snap.PortForwards))

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tIP\tMAC\tVLAN\tVENDOR")
	for _, cl := range snap.Clients {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			cl.DisplayName(), cl.IP, cl.MAC, cl.NetworkName, cl.OUI)
	}
	_ = tw.Flush()

	if len(snap.PortForwards) > 0 {
		fmt.Fprintln(w, "\nPort Forwards:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tENABLED\tPROTO\tWAN PORT\tTARGET\tSRC")
		for _, pf := range snap.PortForwards {
			fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%s:%s\t%s\n",
				pf.Name, pf.Enabled, pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort, pf.Src)
		}
		_ = tw.Flush()
	}
}

// writeJSON encodes v as pretty-printed JSON to w.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
