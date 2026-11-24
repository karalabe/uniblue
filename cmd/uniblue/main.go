// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command uniblue is a blue-team security engine for UniFi networks.
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
	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/classify"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/cve"
	"github.com/karalabe/uniblue/internal/notify"
	"github.com/karalabe/uniblue/internal/oui"
	"github.com/karalabe/uniblue/internal/probe"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/server"
	"github.com/karalabe/uniblue/internal/topology"
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
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "inventory":
		return runInventory(ctx, args[1:], stdout, stderr)
	case "ports":
		return runPorts(ctx, args[1:], stdout, stderr)
	case "topology":
		return runTopology(ctx, args[1:], stdout, stderr)
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "cve":
		return runCVE(ctx, args[1:], stdout, stderr)
	case "oui":
		return runOUI(ctx, args[1:], stdout, stderr)
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
	fmt.Fprintln(w, `UniBlue - Blue-Team Security Engine for UniFi Networks

Usage:
  uniblue <command> [flags]

Commands:
  scan        Run a single UniFi + LAN security scan and print prioritized findings
  watch       Continuously scan on an interval and notify only on new/escalated changes
  serve       Run live event-driven monitor (5s poll / WebSocket) with built-in web UI
  inventory   Fetch and display UniFi clients, devices, VLANs, and port forwards
  ports       Map physical switch ports, external equipment, and perimeter security
  topology    Generate an interactive offline HTML topology report or JSON summary
  check       Validate or test declarative YAML checks against a single host
  cve         Sync, search, and match a local NVD + CISA KEV cache against your LAN
  oui         Sync and query the official IEEE MAC OUI registries (MA-L, MA-M, MA-S)`)
}

// runScan executes one complete UniFi sync, gentle host probe, check pass,
// blast-radius evaluation, and (when a local CVE cache exists) rolled-up CVE
// correlation, printing a unified executive summary to stdout.
func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	jsonOut := fs.Bool("json", false, "output report as JSON")
	saveState := fs.Bool("save-state", false, "persist scan baseline to configured state.path")
	noCVE := fs.Bool("no-cve", false, "skip local CVE cache rollup even if synced")
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

	snap, profiles, report, err := executeCycle(ctx, cfg, checkList)
	if err != nil {
		return err
	}

	// Opportunistically attach rolled-up CVE summaries whenever a local NVD+KEV
	// cache has been synced, giving operators a single unified security picture.
	var exactCVEs, potentialCVEs []cve.ProductSummary
	cveLoaded := false
	if !*noCVE {
		exactCVEs, potentialCVEs, cveLoaded = correlateLocalCVEs(cfg, snap, profiles)
	}

	if *saveState {
		st := risk.BuildState(snap, report, cfg.Network)
		if err := risk.SaveState(cfg.State.Path, st); err != nil {
			return err
		}
	}

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"report":         report,
			"cve_correlated": cveLoaded,
			"exact_cves":     exactCVEs,
			"potential_cves": potentialCVEs,
		})
	}
	printReport(stdout, snap, report, exactCVEs, potentialCVEs, cveLoaded)
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

		snap, _, report, err := executeCycle(ctx, cfg, checkList)
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

// runInventory connects to UniFi and prints the discovered networks, zones,
// UniFi infrastructure uplinks, deterministically classified clients, and port forwards.
func runInventory(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	jsonOut := fs.Bool("json", false, "output inventory snapshot as JSON")
	withProbe := fs.Bool("probe", false, "also probe LAN ports to enrich device classification with protocol proof")
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

	var profiles []probe.HostProfile
	if *withProbe {
		checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
		if err != nil {
			return err
		}
		scanPorts := mergePorts(cfg.Scan.Ports, checkList)
		fp := probe.NewFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet())
		fp.SetHostPortHints(snap.PortHintsByIP())
		profiles = fp.FingerprintAll(ctx, snap.Clients)
	}

	ouiDB := oui.New("")
	_ = ouiDB.Load()
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		return err
	}
	classes := classifier.ClassifyAll(snap, profiles)

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"snapshot":        snap,
			"classifications": classes,
		})
	}
	printInventory(stdout, snap, classes)
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
func executeCycle(ctx context.Context, cfg *config.Config, checkList []*checks.Check) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
	ctrl, err := unifi.New(cfg.UniFi)
	if err != nil {
		return nil, nil, risk.Report{}, err
	}
	if err := ctrl.Login(ctx); err != nil {
		return nil, nil, risk.Report{}, err
	}
	snap, err := ctrl.FetchSnapshot(ctx)
	if err != nil {
		return nil, nil, risk.Report{}, err
	}

	// Union configured default ports with any specialty ports required by loaded
	// community checks so dropping a YAML check into checks/ works automatically.
	scanPorts := mergePorts(cfg.Scan.Ports, checkList)

	fp := probe.NewFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet())
	// Seed per-host port hints from UniFi port forwards, firewall policies, and
	// identity-gated checks (MAC/hostname) so specialty ports are only dialed on
	// matching hosts instead of every host on the LAN.
	fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, checkList, snap.PortHintsByIP()))
	profiles := fp.FingerprintAll(ctx, snap.Clients)

	runner := checks.NewRunner(checkList, cfg.Scan.Concurrency)
	rawFindings := runner.RunAll(ctx, profiles)

	// Merge noise-filtered Nerva protocol findings (e.g., legacy protocols,
	// anonymous service access, expired TLS certs) so they receive UniFi
	// blast-radius scoring, state diffing, and watch alerting alongside YAML checks.
	rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)

	report := risk.Evaluate(snap, rawFindings, cfg.Network)
	return snap, profiles, report, nil
}

// correlateLocalCVEs checks whether the local NVD+KEV cache exists and, if so,
// returns deterministic per-(host, product) rollups split into Exact version
// matches and Potential (version-unknown) patch reminders.
func correlateLocalCVEs(cfg *config.Config, snap *unifi.Snapshot, profiles []probe.HostProfile) (exact, potential []cve.ProductSummary, ok bool) {
	cache := cve.NewCache(cfg.CVE.CacheDir)
	if _, err := cache.Stats(); err != nil {
		return nil, nil, false
	}
	identifier, err := cve.LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		return nil, nil, false
	}
	products := identifier.Identify(snap, profiles)
	matches, err := cache.MatchProducts(products, cve.MatchOptions{
		MinSeverity:          checks.SeverityHigh,
		PotentialMaxAgeYears: 2,
	})
	if err != nil {
		return nil, nil, false
	}
	for _, s := range cve.RollupMatches(matches) {
		if s.Confidence == cve.ConfidenceExact {
			exact = append(exact, s)
		} else {
			potential = append(potential, s)
		}
	}
	return exact, potential, true
}

// mergePorts returns the bounded global baseline TCP port list combining
// basePorts with only those loaded checks that require global TCP probing
// (excluding passive, UDP-only, discovery-only, and identity-gated checks).
func mergePorts(basePorts []int, list []*checks.Check) []int {
	return checks.PlanGlobalPorts(basePorts, list)
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

// printReport renders a unified, operator-ready security summary combining
// confirmed live check findings, exact-version CVE rollups, classified WAN
// exposure, version-unknown patch checks, and clean-posture statistics.
func printReport(w io.Writer, snap *unifi.Snapshot, report risk.Report, exactCVEs, potentialCVEs []cve.ProductSummary, cveLoaded bool) {
	fmt.Fprintf(w, "UniBlue Security Summary | Site: %s (%s) | Clients: %d | UniFi Gear: %d | Networks: %d\n\n",
		snap.Site, snap.ControllerType, report.ClientCount, report.UniFiDeviceCount, len(snap.Networks))

	// 1. Confirmed Actionable LAN Findings (active checks + exact-version CVEs).
	var activeChecks []checks.Finding
	var firmwareFindings []checks.Finding
	for _, f := range report.Findings {
		switch f.CheckID {
		case "UB-UNIFI-PORTFWD":
			// Shown cleanly in the dedicated WAN Surface section below.
		case "UB-UNIFI-FIRMWARE":
			firmwareFindings = append(firmwareFindings, f)
		default:
			activeChecks = append(activeChecks, f)
		}
	}

	fmt.Fprintf(w, "1. Confirmed LAN Exposures (%d check(s), %d exact-version CVE rollup(s)):\n", len(activeChecks), len(exactCVEs))
	if len(activeChecks) == 0 && len(exactCVEs) == 0 {
		fmt.Fprintln(w, "  None detected.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tSOURCE\tHOST\tIP:PORT\tVLAN\tVERIFIED FINDING")
		for _, f := range activeChecks {
			ipPort := f.Client.IP
			if f.Port > 0 {
				ipPort = fmt.Sprintf("%s:%d", f.Client.IP, f.Port)
			}
			vlan := f.Client.NetworkName
			if vlan == "" {
				vlan = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
				strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Client.DisplayName(), ipPort, vlan, f.Title)
		}
		for _, s := range exactCVEs {
			vlan := s.Product.VLAN
			if vlan == "" {
				vlan = "-"
			}
			fmt.Fprintf(tw, "  %s\tCVE-EXACT\t%s\t%s\t%s\t%s\n",
				strings.ToUpper(s.MaxSeverity.String()), s.Product.HostName, s.Product.HostIP, vlan, s.Headline())
		}
		_ = tw.Flush()

		fmt.Fprintln(w, "\n  Verified Proof & Remediation:")
		for _, f := range activeChecks {
			fmt.Fprintf(w, "  - [%s] %s on %s (%s)\n",
				strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Client.DisplayName(), f.Client.IP)
			fmt.Fprintf(w, "    Proof:       %s\n", f.Evidence)
			if len(f.RiskReasons) > 0 {
				fmt.Fprintf(w, "    BlastRadius: %s\n", strings.Join(f.RiskReasons, "; "))
			}
			if f.Remediation.Summary != "" {
				fmt.Fprintf(w, "    Action:      %s\n", strings.TrimSpace(f.Remediation.Summary))
			}
		}
		for _, s := range exactCVEs {
			fmt.Fprintf(w, "  - [%s] %s on %s (%s): %s (top: %s)\n",
				strings.ToUpper(s.MaxSeverity.String()), s.Product.Label, s.Product.HostName, s.Product.HostIP, s.Headline(), strings.Join(s.TopCVEs, ", "))
		}
	}

	// 2. Classified WAN Surface (separating dangerous forwards from expected P2P/VPN).
	fmt.Fprintf(w, "\n2. WAN Exposure Surface (%d enabled forward(s)):\n", len(report.WANSurface))
	if len(report.WANSurface) == 0 {
		fmt.Fprintln(w, "  No active WAN port forwards.")
	} else {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tCLASS\tRULE\tWAN -> TARGET\tHOST\tASSESSMENT")
		for _, a := range report.WANSurface {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s:%s -> %s:%s\t%s\t%s\n",
				strings.ToUpper(a.Severity.String()),
				a.Class,
				a.Forward.Name,
				a.Forward.Proto, a.Forward.DstPort, a.Forward.FwdIP, a.Forward.FwdPort,
				a.Client.DisplayName(),
				a.RuleName,
			)
		}
		_ = tw.Flush()
	}

	// 3. Rolled-up Patch Verification Reminders (version unknown).
	if cveLoaded && len(potentialCVEs) > 0 {
		fmt.Fprintf(w, "\n3. Patch Verification — Version Unknown (%d product(s)):\n", len(potentialCVEs))
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  MAX SEV\tHOST\tVLAN\tSUMMARY\tTOP CVES")
		for _, s := range potentialCVEs {
			vlan := s.Product.VLAN
			if vlan == "" {
				vlan = "-"
			}
			fmt.Fprintf(tw, "  %s\t%s (%s)\t%s\t%s\t%s\n",
				strings.ToUpper(s.MaxSeverity.String()),
				s.Product.HostName, s.Product.HostIP,
				vlan,
				s.Headline(),
				strings.Join(s.TopCVEs, ", "),
			)
		}
		_ = tw.Flush()
	}

	// 4. Network Posture & Clean Summary.
	fmt.Fprintln(w, "\n4. Posture & Clean Baseline:")
	for _, n := range report.PostureNotes {
		fmt.Fprintf(w, "  - [%s] %s\n    %s\n", strings.ToUpper(n.Severity.String()), n.Title, n.Detail)
	}
	for _, f := range firmwareFindings {
		fmt.Fprintf(w, "  - [LOW] %s — %s\n", f.Title, f.Evidence)
	}
	fmt.Fprintf(w, "  - [OK] UniFi Infrastructure: %d/%d device(s) up to date\n", report.CleanUniFiDevices, report.UniFiDeviceCount)
	fmt.Fprintf(w, "  - [OK] LAN Clients:          %d/%d active host(s) passed with zero unauthenticated services exposed\n", report.CleanClients, report.ClientCount)
	if !cveLoaded {
		fmt.Fprintln(w, "  - [TIP] Run `uniblue cve sync` once to include offline NVD+KEV correlation in `uniblue scan`.")
	}
}

// printInventory renders the UniFi snapshot tables cleanly for `uniblue inventory`.
func printInventory(w io.Writer, snap *unifi.Snapshot, classes map[string]classify.Result) {
	fmt.Fprintf(w, "UniFi Site: %s (%s) | Clients: %d | Devices: %d | Networks: %d | Zones: %d | Port Forwards: %d\n\n",
		snap.Site, snap.ControllerType, len(snap.Clients), len(snap.Devices), len(snap.Networks), len(snap.Zones), len(snap.PortForwards))

	if len(snap.Networks) > 0 {
		clientsPerNet := make(map[string]int, len(snap.Networks))
		for _, cl := range snap.Clients {
			if cl.NetworkName != "" {
				clientsPerNet[strings.ToLower(cl.NetworkName)]++
			}
		}
		fmt.Fprintln(w, "Networks & Topology:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tVLAN\tZONE\tPURPOSE\tISOLATED\tSUBNET\tCLIENTS")
		for _, n := range snap.Networks {
			zone := n.ZoneName
			if zone == "" {
				zone = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%s\t%d\n",
				n.Name, n.VLAN, zone, n.Purpose, n.IsolationEnabled, n.Subnet, clientsPerNet[strings.ToLower(n.Name)])
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	if len(snap.Devices) > 0 {
		fmt.Fprintln(w, "UniFi Infrastructure:")
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "DEVICE\tMODEL\tIP\tFIRMWARE\tUPLINK")
		for _, d := range snap.Devices {
			uplink := "-"
			if d.UplinkName != "" {
				uplink = d.UplinkName
				if d.UplinkPort > 0 {
					uplink = fmt.Sprintf("%s (port %d)", d.UplinkName, d.UplinkPort)
				}
			}
			ver := d.Version
			if d.Upgradable {
				ver += " (update)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.Name, d.Model, d.IP, ver, uplink)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	devNameByMAC := make(map[string]string, len(snap.Devices))
	for _, d := range snap.Devices {
		if d.MAC != "" {
			devNameByMAC[strings.ToLower(d.MAC)] = d.Name
		}
	}

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tIP\tVLAN\tCATEGORY\tROLE\tVENDOR\tLINK")
	for _, cl := range snap.Clients {
		key := cl.IP
		if key == "" {
			key = cl.MAC
		}
		res := classes[key]
		vendor := res.Vendor
		if vendor == "" {
			vendor = "-"
		}
		link := "Wi-Fi"
		if cl.IsWired {
			link = "Wired"
			if cl.SwitchPort > 0 {
				sw := devNameByMAC[cl.SwitchMAC]
				if sw != "" {
					link = fmt.Sprintf("%s:%d", sw, cl.SwitchPort)
				} else {
					link = fmt.Sprintf("port %d", cl.SwitchPort)
				}
			}
		} else if cl.ESSID != "" {
			link = "Wi-Fi:" + cl.ESSID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			cl.DisplayName(), cl.IP, cl.NetworkName, res.Category, res.Role, vendor, link)
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

// runCVE dispatches `uniblue cve <sync|explore|search|show>` subcommands.
func runCVE(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: uniblue cve <sync|explore|search|show> [flags]")
	}
	switch args[0] {
	case "sync":
		return runCVESync(ctx, args[1:], stdout, stderr)
	case "explore":
		return runCVEExplore(ctx, args[1:], stdout, stderr)
	case "search":
		return runCVESearch(ctx, args[1:], stdout, stderr)
	case "show":
		return runCVEShow(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown cve subcommand %q (want sync, explore, search, or show)", args[0])
	}
}

// runCVESync downloads CISA KEV and NVD JSON 2.0 yearly feeds into the local
// vendor-sharded cache and prints storage and timing metrics.
func runCVESync(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cacheDir := fs.String("cache", cve.DefaultCacheDir(), "local CVE cache directory")
	since := fs.Int("since", 2002, "earliest NVD year to download (2002 = full database)")
	force := fs.Bool("force", false, "re-download and re-index even if feeds are unchanged")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cache := cve.NewCache(*cacheDir)
	stats, err := cache.Sync(ctx, cve.SyncOptions{
		SinceYear: *since,
		Force:     *force,
		Progress: func(msg string) {
			fmt.Fprintln(stderr, msg)
		},
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "\nCVE Cache Ready (%s)\n", cache.Dir())
	fmt.Fprintf(stdout, "  Total CVEs parsed:    %d (%d with CPEs)\n", stats.TotalCVEs, stats.IndexedCPECVEs)
	fmt.Fprintf(stdout, "  Vendor shards:        %d\n", stats.VendorCount)
	fmt.Fprintf(stdout, "  CISA KEV catalog:     %d\n", stats.KEVCount)
	fmt.Fprintf(stdout, "  Raw NVD feeds size:   %.1f MB\n", float64(stats.RawFeedBytes)/(1024*1024))
	fmt.Fprintf(stdout, "  Compiled index size:  %.1f MB\n", float64(stats.IndexBytes)/(1024*1024))
	fmt.Fprintf(stdout, "  Elapsed:              %.1fs\n", float64(stats.ElapsedMS)/1000)
	return nil
}

// runCVEExplore fingerprints UniFi gear and active LAN hosts, maps them to
// canonical products, and matches them against the local CVE cache.
func runCVEExplore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve explore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	cacheDir := fs.String("cache", "", "local CVE cache directory (overrides config)")
	minSevStr := fs.String("min-severity", "high", "minimum CVE severity (info, low, medium, high, critical)")
	recentYears := fs.Int("recent-years", 2, "limit version-unknown non-KEV matches to CVEs published in the last N years (0 = all)")
	limit := fs.Int("limit", 40, "max potential (version-unknown) CVEs to print")
	jsonOut := fs.Bool("json", false, "output matches as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	minSev, err := checks.ParseSeverity(*minSevStr)
	if err != nil {
		return err
	}
	dir := *cacheDir
	if dir == "" {
		dir = cfg.CVE.CacheDir
	}
	cache := cve.NewCache(dir)
	stats, err := cache.Stats()
	if err != nil {
		return fmt.Errorf("cve cache not ready at %q (run `uniblue cve sync` first): %w", cache.Dir(), err)
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

	fp := probe.NewFingerprinter(cfg.Scan.Ports, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet())
	profiles := fp.FingerprintAll(ctx, snap.Clients)

	identifier, err := cve.LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		return err
	}
	products := identifier.Identify(snap, profiles)

	matches, err := cache.MatchProducts(products, cve.MatchOptions{
		MinSeverity:          minSev,
		PotentialMaxAgeYears: *recentYears,
	})
	if err != nil {
		return err
	}

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"cache_stats": stats,
			"products":    products,
			"matches":     matches,
		})
	}

	fmt.Fprintf(stdout, "UniBlue CVE Explorer | Cache: %d CVEs (%d KEV) | Detected Products: %d\n\n",
		stats.TotalCVEs, stats.KEVCount, len(products))

	// Show every fingerprinted software/hardware item so operators can audit
	// exactly what UniBlue detected on their LAN.
	fmt.Fprintln(stdout, "Detected Software & Hardware:")
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tIP\tVLAN\tPRODUCT\tVERSION\tSOURCE")
	for _, p := range products {
		ver := p.Version
		if ver == "" {
			ver = "(unknown)"
		}
		vlan := p.VLAN
		if vlan == "" {
			vlan = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.HostName, p.HostIP, vlan, p.Label, ver, p.Source)
	}
	_ = tw.Flush()

	var exact, potential []cve.Match
	for _, m := range matches {
		if m.Confidence == cve.ConfidenceExact {
			exact = append(exact, m)
		} else {
			potential = append(potential, m)
		}
	}

	fmt.Fprintf(stdout, "\nExact Version CVE Matches (%d):\n", len(exact))
	if len(exact) == 0 {
		fmt.Fprintln(stdout, "  None detected for observed exact versions.")
	} else {
		printCVEMatchTable(stdout, exact, len(exact))
	}

	fmt.Fprintf(stdout, "\nPotential Product Matches — Version Unknown (%d total, showing up to %d):\n", len(potential), *limit)
	if len(potential) == 0 {
		fmt.Fprintln(stdout, "  None.")
	} else {
		printCVEMatchTable(stdout, potential, *limit)
	}
	return nil
}

// runCVESearch performs an offline search across the local CVE cache.
func runCVESearch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cacheDir := fs.String("cache", cve.DefaultCacheDir(), "local CVE cache directory")
	vendor := fs.String("vendor", "", "restrict search to one CPE vendor shard")
	kevOnly := fs.Bool("kev", false, "show only CISA KEV actively exploited CVEs")
	minSevStr := fs.String("min-severity", "low", "minimum severity (info, low, medium, high, critical)")
	limit := fs.Int("limit", 30, "maximum number of results")
	if err := fs.Parse(args); err != nil {
		return err
	}

	minSev, err := checks.ParseSeverity(*minSevStr)
	if err != nil {
		return err
	}
	query := strings.Join(fs.Args(), " ")
	if query == "" && *vendor == "" && !*kevOnly {
		return errors.New("cve search requires a query, -vendor, or -kev")
	}

	cache := cve.NewCache(*cacheDir)
	recs, err := cache.Search(ctx, query, cve.SearchOptions{
		Vendor:      *vendor,
		KEVOnly:     *kevOnly,
		MinSeverity: minSev,
		Limit:       *limit,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Found %d CVE(s) (limit %d):\n\n", len(recs), *limit)
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CVE\tSEV\tCVSS\tKEV\tPUBLISHED\tSUMMARY")
	for _, r := range recs {
		kev := ""
		if r.KEV {
			kev = "KEV"
		}
		summary := r.Description
		if len(summary) > 95 {
			summary = summary[:92] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%s\t%s\t%s\n",
			r.ID, strings.ToUpper(r.Severity.String()), r.CVSS, kev, r.Published, summary)
	}
	_ = tw.Flush()
	return nil
}

// runCVEShow prints full cached details and affected CPE version ranges for a
// single CVE identifier without hitting the network.
func runCVEShow(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cacheDir := fs.String("cache", cve.DefaultCacheDir(), "local CVE cache directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: uniblue cve show [-cache <dir>] <CVE-ID>")
	}

	cache := cve.NewCache(*cacheDir)
	rec, err := cache.LookupCVE(ctx, fs.Arg(0))
	if err != nil {
		return err
	}

	kevTag := "no"
	if rec.KEV {
		kevTag = "YES (CISA Known Exploited)"
	}
	fmt.Fprintf(stdout, "%s\n", rec.ID)
	fmt.Fprintf(stdout, "  Severity:   %s (CVSS %.1f)\n", strings.ToUpper(rec.Severity.String()), rec.CVSS)
	fmt.Fprintf(stdout, "  Published:  %s\n", rec.Published)
	fmt.Fprintf(stdout, "  CISA KEV:   %s\n", kevTag)
	fmt.Fprintf(stdout, "  Summary:    %s\n", rec.Description)

	if len(rec.Matches) > 0 {
		fmt.Fprintf(stdout, "\nAffected CPE Ranges (%d):\n", len(rec.Matches))
		for _, m := range rec.Matches {
			fmt.Fprintf(stdout, "  - %s:%s %s\n", m.Vendor, m.Product, formatCPERange(m))
		}
	}
	return nil
}

// formatCPERange renders a CPE match's exact version or bounds compactly.
func formatCPERange(m cve.CPEMatch) string {
	if m.Version != "" {
		return "== " + m.Version
	}
	var parts []string
	if m.StartIncl != "" {
		parts = append(parts, ">= "+m.StartIncl)
	}
	if m.StartExcl != "" {
		parts = append(parts, "> "+m.StartExcl)
	}
	if m.EndIncl != "" {
		parts = append(parts, "<= "+m.EndIncl)
	}
	if m.EndExcl != "" {
		parts = append(parts, "< "+m.EndExcl)
	}
	if len(parts) == 0 {
		return "(all versions)"
	}
	return strings.Join(parts, ", ")
}

// printCVEMatchTable renders a compact, readable table of CVE matches.
func printCVEMatchTable(w io.Writer, matches []cve.Match, maxRows int) {
	if len(matches) > maxRows {
		matches = matches[:maxRows]
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CVE\tSEV\tCVSS\tKEV\tHOST\tPRODUCT\tSUMMARY")
	for _, m := range matches {
		kev := ""
		if m.Record.KEV {
			kev = "KEV"
		}
		prod := m.Product.Label
		if m.Product.Version != "" {
			prod = fmt.Sprintf("%s %s", prod, m.Product.Version)
		}
		summary := m.Record.Description
		if len(summary) > 78 {
			summary = summary[:75] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%s\t%s (%s)\t%s\t%s\n",
			m.Record.ID,
			strings.ToUpper(m.Record.Severity.String()),
			m.Record.CVSS,
			kev,
			m.Product.HostName,
			m.Product.HostIP,
			prod,
			summary,
		)
	}
	_ = tw.Flush()
}

// runOUI dispatches `uniblue oui <sync|lookup>` for managing the local official
// IEEE MAC OUI database (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit, and IAB).
func runOUI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: uniblue oui <sync|lookup> [flags]")
	}
	switch args[0] {
	case "sync":
		fs := flag.NewFlagSet("oui sync", flag.ContinueOnError)
		fs.SetOutput(stderr)
		cacheDir := fs.String("cache", oui.DefaultCacheDir(), "local IEEE OUI cache directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		db := oui.New(*cacheDir)
		meta, err := db.Sync(ctx, func(msg string) {
			fmt.Fprintln(stderr, msg)
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "\nIEEE OUI Cache Ready (%s)\n", db.Dir())
		fmt.Fprintf(stdout, "  MA-L (24-bit):  %d\n", meta.MALCount)
		fmt.Fprintf(stdout, "  MA-M (28-bit):  %d\n", meta.MAMCount)
		fmt.Fprintf(stdout, "  MA-S/IAB (36b): %d\n", meta.MASCount)
		fmt.Fprintf(stdout, "  Total entries:  %d (%.1f KB compiled)\n", meta.TotalEntries, float64(meta.CompiledBytes)/1024)
		return nil

	case "lookup":
		fs := flag.NewFlagSet("oui lookup", flag.ContinueOnError)
		fs.SetOutput(stderr)
		cacheDir := fs.String("cache", oui.DefaultCacheDir(), "local IEEE OUI cache directory")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return errors.New("usage: uniblue oui lookup <mac> [mac...]")
		}
		db := oui.New(*cacheDir)
		if err := db.Load(); err != nil {
			return err
		}
		for _, mac := range fs.Args() {
			res := db.Lookup(mac)
			vendor := res.Vendor
			if vendor == "" {
				vendor = "(unknown)"
			}
			fmt.Fprintf(stdout, "%-20s %-8s %-10s %s (local=%v, virtual=%v)\n",
				mac, res.Registry, res.Prefix, vendor, res.IsLocallyAdministered, res.IsVirtual)
		}
		return nil

	default:
		return fmt.Errorf("unknown oui subcommand %q (want sync or lookup)", args[0])
	}
}

// runTopology builds a deterministic network topology & security presentation
// model from UniFi zones, VLANs, switch ports, LLDP uplinks, IEEE OUI data, and
// (unless -no-probe is set) gentle service fingerprinting, then outputs either
// a self-contained offline interactive HTML snapshot (-out), JSON, or a concise
// terminal placement summary.
func runTopology(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("topology", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	outPath := fs.String("out", "", "path to write self-contained interactive HTML report (use '-' for stdout)")
	jsonOut := fs.Bool("json", false, "output topology model as JSON")
	noProbe := fs.Bool("no-probe", false, "skip active LAN port probing (classify from UniFi + IEEE OUI only)")
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

	var profiles []probe.HostProfile
	var rawFindings []checks.Finding
	if !*noProbe {
		checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
		if err != nil {
			return err
		}
		scanPorts := mergePorts(cfg.Scan.Ports, checkList)
		fp := probe.NewFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet())
		fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, checkList, snap.PortHintsByIP()))
		profiles = fp.FingerprintAll(ctx, snap.Clients)
		runner := checks.NewRunner(checkList, cfg.Scan.Concurrency)
		rawFindings = runner.RunAll(ctx, profiles)
		rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)
	}

	ouiDB := oui.New("")
	_ = ouiDB.Load()
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		return err
	}
	classes := classifier.ClassifyAll(snap, profiles)
	model := topology.Build(snap, classes, cfg.Network)

	if *jsonOut {
		return writeJSON(stdout, model)
	}
	if *outPath != "" {
		report := risk.Evaluate(snap, rawFindings, cfg.Network)
		exactCVEs, potentialCVEs, cveLoaded := correlateLocalCVEs(cfg, snap, profiles)

		profileByMAC := make(map[string]probe.HostProfile, len(profiles))
		for _, hp := range profiles {
			k := strings.ToLower(hp.Client.MAC)
			if k == "" {
				k = hp.Client.IP
			}
			profileByMAC[k] = hp
		}
		clientViews := make([]server.ClientView, 0, len(snap.Clients))
		for _, cl := range snap.Clients {
			k := strings.ToLower(cl.MAC)
			if k == "" {
				k = cl.IP
			}
			clsKey := cl.IP
			if clsKey == "" {
				clsKey = cl.MAC
			}
			cv := server.ClientView{
				Client:      cl,
				Class:       classes[clsKey],
				MaxSeverity: "clean",
			}
			if hp, ok := profileByMAC[k]; ok {
				cv.OpenPorts = hp.OpenPorts
				ts := hp.ScannedAt
				cv.LastScannedAt = &ts
			}
			clientViews = append(clientViews, cv)
		}
		now := time.Now().UTC()
		stateSnap := server.StateSnapshot{
			StartedAt:      now,
			UpdatedAt:      now,
			LastFullScanAt: now,
			EventMode:      "static-export",
			Site:           snap.Site,
			ControllerType: snap.ControllerType,
			CVELoaded:      cveLoaded,
			Report:         report,
			ExactCVEs:      exactCVEs,
			PotentialCVEs:  potentialCVEs,
			Topology:       model,
			Clients:        clientViews,
			View:           server.BuildPresentationModel(snap, report, model, clientViews, exactCVEs, potentialCVEs, profiles),
		}
		if *outPath == "-" {
			return server.RenderStaticHTML(stdout, stateSnap)
		}
		var buf strings.Builder
		if err := server.RenderStaticHTML(&buf, stateSnap); err != nil {
			return err
		}
		if err := os.WriteFile(*outPath, []byte(buf.String()), 0o644); err != nil {
			return fmt.Errorf("write topology html %q: %w", *outPath, err)
		}
		fmt.Fprintf(stdout, "Wrote interactive offline topology report to %s (%d VLANs, %d clients, %d UniFi devices)\n",
			*outPath, len(model.VLANs), model.ClientCount, model.DeviceCount)
		return nil
	}

	// Print a compact terminal topology placement summary when -out is omitted.
	fmt.Fprintf(stdout, "UniFi Topology | Site: %s | VLANs: %d | Clients: %d | Devices: %d\n\n",
		model.Site, len(model.VLANs), model.ClientCount, model.DeviceCount)
	for _, vg := range model.VLANs {
		fmt.Fprintf(stdout, "%s (VLAN %s · %s · zone=%s · %d client(s))\n",
			vg.Name, vg.VLAN, vg.Subnet, vg.ZoneName, len(vg.Clients))
		if len(vg.Clients) == 0 {
			fmt.Fprintln(stdout, "  (empty)")
			continue
		}
		tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
		for _, cl := range vg.Clients {
			note := cl.PlacementReason
			if note == "" {
				note = cl.Class.Role
			}
			fmt.Fprintf(tw, "  %-8s\t%-10s\t%s\t%s\t%s\n",
				strings.ToUpper(string(cl.Placement)), cl.Class.Category, cl.Name, cl.IP, note)
		}
		_ = tw.Flush()
	}
	fmt.Fprintln(stdout, "\nTip: pass -out topology.html to export a self-contained interactive HTML report.")
	return nil
}

// runServe starts UniBlue's live event-driven monitoring server, reacting to
// UniFi client joins/leaves/moves and firewall changes in real time (via native
// WebSocket on cookie auth or fast 5s delta polling on API key auth) while
// serving a lightweight live web UI and JSON/SSE API.
func runServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address for the built-in web UI")
	poll := fs.Duration("poll", 5*time.Second, "UniFi topology delta poll interval (when WebSocket is unavailable)")
	reconcile := fs.Duration("reconcile", 30*time.Minute, "periodic full LAN reconciliation interval")
	noCVE := fs.Bool("no-cve", false, "skip local CVE cache correlation even if synced")
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
	scanPorts := mergePorts(cfg.Scan.Ports, checkList)

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	eng, err := server.NewEngine(cfg, checkList, scanPorts, server.Options{
		ListenAddr:        *listen,
		PollInterval:      *poll,
		ReconcileInterval: *reconcile,
		SkipCVE:           *noCVE,
		Logger:            logger,
	})
	if err != nil {
		return err
	}
	if err := eng.Start(ctx); err != nil {
		return err
	}
	return eng.Serve(ctx)
}

// runPorts connects to UniFi, maps every switch/gateway/In-Wall AP physical
// port (link state, VLAN tagging, PoE, MAC lock, connected peers, and
// external-world perimeter zoning), and prints a security-annotated port table.
func runPorts(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ports", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "path to UniBlue YAML config file")
	jsonOut := fs.Bool("json", false, "output physical port analysis as JSON")
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

	report := risk.Evaluate(snap, nil, cfg.Network)
	var portFindings []checks.Finding
	for _, f := range report.Findings {
		if strings.HasPrefix(f.CheckID, "UB-UNIFI-PORT-") {
			portFindings = append(portFindings, f)
		}
	}

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"site":          snap.Site,
			"switches":      report.SwitchPorts,
			"findings":      portFindings,
			"posture_notes": report.PostureNotes,
		})
	}
	printSwitchPorts(stdout, snap.Site, report.SwitchPorts, portFindings)
	return nil
}

// printSwitchPorts renders a concise physical port allocation & security table
// for every UniFi switch, gateway, and In-Wall AP.
func printSwitchPorts(w io.Writer, site string, switches []risk.SwitchDeviceView, findings []checks.Finding) {
	var total, active, inactiveOpen, disabled, external, atRisk int
	for _, sw := range switches {
		total += sw.TotalPorts
		active += sw.ActivePorts
		inactiveOpen += sw.InactiveEnabledPorts
		disabled += sw.DisabledPorts
		external += sw.ExternalPorts
		atRisk += sw.AtRiskPorts
	}
	fmt.Fprintf(w, "UniBlue Switch Port Map | Site: %s | Devices: %d | Ports: %d total (%d active, %d unused-open, %d disabled) | External: %d | At-Risk: %d\n\n",
		site, len(switches), total, active, inactiveOpen, disabled, external, atRisk)

	for _, sw := range switches {
		extTag := ""
		if sw.ExternalDevice {
			extTag = fmt.Sprintf(" [EXTERNAL EQUIPMENT (%s)]", sw.ZoneSource)
		}
		uplink := "Root Gateway"
		if sw.UplinkName != "" {
			uplink = sw.UplinkName
			if sw.UplinkPort > 0 {
				uplink = fmt.Sprintf("%s Port %d", sw.UplinkName, sw.UplinkPort)
			}
		}
		fmt.Fprintf(w, "%s (%s · %s)%s — Uplink: %s | %d active, %d unused-open, %d disabled\n",
			sw.Name, sw.Model, sw.IP, extTag, uplink, sw.ActivePorts, sw.InactiveEnabledPorts, sw.DisabledPorts)

		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "  PORT\tSTATE\tZONE\tNATIVE VLAN\tTAGGED\tMAC LOCK\tPOE\tPEER(S)\tSTATUS")
		for _, p := range sw.Ports {
			state := "INACTIVE"
			switch p.State {
			case "active":
				if p.Speed >= 1000 {
					state = fmt.Sprintf("UP %dG", p.Speed/1000)
				} else if p.Speed > 0 {
					state = fmt.Sprintf("UP %dM", p.Speed)
				} else {
					state = "UP"
				}
			case "disabled":
				state = "DISABLED"
			}
			vlan := p.NativeVLAN
			if vlan == "" {
				vlan = "-"
			}
			macLock := "off"
			if p.PortSecurity {
				macLock = "ON"
			}
			poe := "-"
			if p.PoEEnabled {
				if p.PoEPower != "" {
					poe = p.PoEPower + "W"
				} else {
					poe = "ON"
				}
			}
			peerStr := "-"
			if len(p.Peers) > 0 {
				parts := make([]string, 0, len(p.Peers))
				for _, peer := range p.Peers {
					if peer.IP != "" {
						parts = append(parts, fmt.Sprintf("%s (%s)", peer.Name, peer.IP))
					} else {
						parts = append(parts, peer.Name)
					}
				}
				peerStr = strings.Join(parts, ", ")
			} else if p.Label != "" {
				peerStr = p.Label
			}
			status := strings.ToUpper(p.Status)
			if len(p.Issues) > 0 {
				status = fmt.Sprintf("%s: %s", status, strings.Join(p.Issues, "; "))
			}
			fmt.Fprintf(tw, "  #%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				p.PortIdx, state, strings.ToUpper(p.Zone), vlan, p.TaggedPolicy, macLock, poe, peerStr, status)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}

	if len(findings) > 0 {
		fmt.Fprintf(w, "Physical Port Security Alerts (%d):\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(w, "  - [%s] %s: %s\n", strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Title)
			fmt.Fprintf(w, "    Proof:  %s\n", f.Evidence)
			fmt.Fprintf(w, "    Action: %s\n", f.Remediation.Summary)
		}
	}
}
