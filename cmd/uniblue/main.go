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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	builtinchecks "github.com/karalabe/uniblue/checks"
	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/fingerprints"
	"github.com/karalabe/uniblue/internal/blast"
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
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
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
	case "blast":
		return runBlast(ctx, args[1:], stdout, stderr)
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr)
	case "watch":
		return runWatch(ctx, args[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, args[1:], stdout, stderr)
	case "demo":
		return runDemo(ctx, args[1:], stdout, stderr)
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
  blast       Show which network changes would reduce exposure
  scan        Run a single UniFi + LAN security scan and print prioritized findings
  watch       Continuously scan on an interval and notify only on new/escalated changes
  serve       Run live event-driven monitor (5s poll / WebSocket) with built-in web UI
  demo        Run built-in web UI seeded with a realistic offline demo network
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
	if *saveState {
		if err := verifyStatePathWritable(cfg.State.Path); err != nil {
			return fmt.Errorf("state path %q is not writable (set state.path to a writable file): %w", cfg.State.Path, err)
		}
	}
	checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
	if err != nil {
		return err
	}

	snap, profiles, rawFindings, devChildren, report, err := executeCycleDetailed(ctx, cfg, checkList, nil, nil)
	if err != nil {
		return err
	}

	// Optionally correlate detected software against the local offline CVE
	// cache when synced, plus collect high-profile target velocity signals for
	// the 3-lane action queue without altering finding severities.
	var exactCVEs, potentialCVEs []cve.ProductSummary
	var rawCVEMatches []cve.Match
	var targetSignals []blast.TargetSignal
	cveLoaded := false
	if !*noCVE {
		if matches, signals, err := localCVEMatchesAndSignals(cfg, snap, profiles); err == nil {
			cveLoaded = true
			rawCVEMatches = matches
			targetSignals = signals
			for _, s := range cve.RollupMatches(matches) {
				if s.Confidence == cve.ConfidenceExact {
					exactCVEs = append(exactCVEs, s)
				} else {
					potentialCVEs = append(potentialCVEs, s)
				}
			}
		}
	}
	ctrlHost := ""
	if u, err := url.Parse(cfg.UniFi.URL); err == nil {
		ctrlHost = u.Hostname()
	}
	blastProfiles := server.AppendDeviceChildProfiles(snap, profiles, devChildren)
	blastRep, _ := server.EvaluateSiteBlast(snap, blastProfiles, rawFindings, report, cfg.Network, checkList, rawCVEMatches, targetSignals, ctrlHost)

	if *saveState {
		if !cfg.State.ExplicitPath {
			warnLegacyCWDState(slog.New(slog.NewTextHandler(stderr, nil)), cfg.State.Path)
		}
		prev, _ := risk.LoadState(cfg.State.Path)
		st := risk.BuildStateWithPrev(prev, snap, report, cfg.Network, probedHostKeys(profiles))
		if err := risk.SaveState(cfg.State.Path, st); err != nil {
			return err
		}
	}

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"report":           report,
			"blast":            blastRep,
			"profiles":         profiles,
			"service_coverage": probe.ComputeServiceCoverage(profiles),
			"cve_correlated":   cveLoaded,
			"exact_cves":       exactCVEs,
			"potential_cves":   potentialCVEs,
		})
	}
	printReport(stdout, snap, report, &blastRep, profiles, exactCVEs, potentialCVEs, cveLoaded)
	printLocalSSHKeyAudit(stdout, profiles)
	return nil
}

// runBlast evaluates reachability and ranks hypothetical network changes without
// modifying scan state or controller settings.
func runBlast(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("blast", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "config.yaml", "path to the UniBlue configuration")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	noProbe := fs.Bool("no-probe", false, "use controller and passive inventory only")
	compromise := fs.String("compromise", "", "assess loss of an AP, switch, gateway, or controller by name or MAC")
	noCVE := fs.Bool("no-cve", false, "skip the local vulnerability cache")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected blast argument %q", fs.Arg(0))
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	list, err := loadAllChecks(cfg.Scan.ChecksDir)
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

	prev, _ := risk.LoadState(cfg.State.Path)
	activeChecks := list
	var profiles []probe.HostProfile
	if !*noProbe {
		fp := newSiteFingerprinter(mergePorts(cfg.Scan.Ports, list), cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet(), snap)
		if err := fp.SetSSHKeyAudit(cfg.Scan.SSHKeyAudit); err != nil {
			return err
		}
		if prev != nil {
			fp.SetPreviousSSHHostKeys(prev.SSHHostKeys)
		}
		fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, list, snap.PortHintsByIP()))
		profiles = fp.FingerprintAll(ctx, snap.Clients)
	} else {
		// In -no-probe mode, skip active host probes and only run passive observation checks.
		activeChecks = nil
		for _, c := range list {
			if c.Probe.Type == "observe" {
				activeChecks = append(activeChecks, c)
			}
		}
		for _, cl := range snap.Clients {
			profiles = append(profiles, probe.HostProfile{Client: cl})
		}
	}
	children := enrichSiteAndProfiles(snap, profiles, cfg.Network)
	profiles = server.AppendDeviceChildProfiles(snap, profiles, children)
	ctrlURL, err := url.Parse(cfg.UniFi.URL)
	if err != nil {
		return err
	}
	in := blast.Input{Snapshot: snap, Profiles: profiles, NetCfg: cfg.Network, ControllerHost: ctrlURL.Hostname()}
	if *compromise != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := blast.EvaluateInfraCompromise(in, *compromise)
		if err != nil {
			return err
		}
		if *asJSON {
			return writeJSON(stdout, result)
		}
		printInfraBlast(stdout, result)
		return nil
	}
	prev.CompareSSHHostKeys(profiles)
	findings := checks.NewRunner(activeChecks, cfg.Scan.Concurrency).RunAll(ctx, profiles)
	if err := ctx.Err(); err != nil {
		return err
	}
	findings = append(findings, checks.FindingsFromProfiles(profiles, findings)...)
	base := risk.Evaluate(snap, findings, cfg.Network)
	in.Findings, in.Checks = findings, list
	in.Isolation, in.SwitchPorts = base.Isolation, base.SwitchPorts
	if !*noCVE {
		var signals []blast.TargetSignal
		if in.CVEMatches, signals, err = localCVEMatchesAndSignals(cfg, snap, profiles); err != nil {
			fmt.Fprintln(stderr, "Local vulnerability cache unavailable; skipping CVE matches.")
		} else {
			in.TargetSignals = signals
		}
	}
	var warnings []string
	in.Assets, warnings = classify.ResolveAssets(snap, profiles, cfg.Network.Assets)
	for _, msg := range warnings {
		fmt.Fprintln(stderr, msg)
	}
	result := blast.Evaluate(in)
	if *asJSON {
		return writeJSON(stdout, result)
	}
	printBlast(stdout, result)
	printLocalSSHKeyAudit(stdout, profiles)
	return nil
}

// printLocalSSHKeyAudit displays opt-in SSH PK_OK audit details only when
// writing to an interactive terminal. Redirected pipes/logs receive only a
// privacy-safe summary count so key-to-host maps are never captured in logs.
func printLocalSSHKeyAudit(w io.Writer, profiles []probe.HostProfile) {
	isTTY := false
	if f, ok := w.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			isTTY = true
		}
	}
	if !isTTY {
		invitedHosts, noneHosts := 0, 0
		for _, hp := range profiles {
			if hp.SSH == nil || hp.SSH.CanaryFalsePositive {
				continue
			}
			if hp.SSH.NoneAuthAccepted {
				noneHosts++
			} else if len(hp.SSH.AcceptedKeys) > 0 {
				invitedHosts++
			}
		}
		if noneHosts > 0 || invitedHosts > 0 {
			fmt.Fprintf(w, "\nSSH key audit summary: %d host(s) accepted 'none' auth, %d host(s) invited configured public keys (run in an interactive terminal to view key details).\n", noneHosts, invitedHosts)
		}
		return
	}
	headerPrinted := false
	ensureHeader := func() {
		if !headerPrinted {
			fmt.Fprintln(w, "\nSSH key audit (local only, omitted from JSON and webhooks)")
			headerPrinted = true
		}
	}
	for _, hp := range profiles {
		s := hp.SSH
		if s == nil {
			continue
		}
		name := hp.Client.DisplayName()
		if s.CanaryFalsePositive {
			ensureHeader()
			fmt.Fprintf(w, "  %s (port %d): server accepted a random canary key; key matches discarded.\n", name, s.Port)
			continue
		}
		for _, k := range s.AcceptedKeys {
			ensureHeader()
			if k.Method == "none" {
				fmt.Fprintf(w, "  %s (port %d): accepted unauthenticated 'none' login for user %q.\n", name, s.Port, k.Username)
			} else {
				fmt.Fprintf(w, "  %s (port %d): user %q invited %s (%s, %s) - %s\n", name, s.Port, k.Username, k.KeyLabel, k.Fingerprint, k.Algorithm, k.Note)
			}
		}
		if s.BruteForceProtected {
			ensureHeader()
			fmt.Fprintf(w, "  %s (port %d): connection rate-limited or dropped during audit (stopped early).\n", name, s.Port)
		}
	}
}

// printInfraBlast prints the direction and three properties of each leg. All
// resilient rows share the same six limitations, printed together below them.
func printInfraBlast(w io.Writer, r blast.InfraReport) {
	fmt.Fprintf(w, "%s compromise: %s\n", r.Scope, r.Target)
	for _, effect := range r.Effects {
		fmt.Fprintln(w, effect)
	}
	if r.HostedOn != "" {
		fmt.Fprintln(w, "Controller runs on:", r.HostedOn)
	}
	for _, row := range []struct {
		label  string
		values []string
	}{
		{"Controller manages", r.Manages}, {"Downstream devices", r.Downstream}, {"Routed VLANs", r.RoutedVLANs}, {"Affected clients", r.Clients},
	} {
		if len(row.values) > 0 {
			fmt.Fprintf(w, "%s: %s\n", row.label, strings.Join(row.values, ", "))
		}
	}
	if len(r.Ports) > 0 {
		fmt.Fprintln(w, "Switch ports:", r.Ports)
	}
	if r.Scope == "AP" || r.Scope == "Switch" {
		nets := strings.Join(r.UplinkVLANs, ", ")
		if r.UplinkUnknown {
			if nets != "" {
				nets += ", other VLANs unknown"
			} else {
				nets = "unknown"
			}
		} else if nets == "" {
			nets = "none"
		}
		fmt.Fprintf(w, "%s uplink carries VLANs: %s\n", r.Scope, nets)
	}
	if len(r.Legs) == 0 {
		fmt.Fprintln(w, "No service observations were available on the affected paths.")
	}
	var blindSpots []string
	for _, l := range r.Legs {
		endpoint := l.Address
		if l.Port > 0 {
			endpoint = strings.TrimSpace(fmt.Sprintf("%s %s/%d", endpoint, l.Transport, l.Port))
		}
		fmt.Fprintf(w, "\n%s -> %s (%s) %s\n  %s. Reachability: %s. Transport: %s.\n", l.From, l.To, l.Protocol, endpoint, l.Path, l.Reachability, l.Class)
		fmt.Fprintf(w, "  Confidentiality: %s. Integrity: %s. Availability: %s.\n  %s\n", l.Confidentiality, l.Integrity, l.Availability, l.Note)
		if l.Wireless != "" {
			fmt.Fprintln(w, " ", l.Wireless)
		}
		for _, v := range []blast.TransportVerdict{l.Confidentiality, l.Integrity, l.Availability} {
			if spots := v.BlindSpots(); len(spots) != 0 {
				blindSpots = spots
			}
		}
	}
	if len(blindSpots) != 0 {
		fmt.Fprintln(w, "\nLimits of every resilient verdict above")
		for _, item := range blindSpots {
			fmt.Fprintln(w, "-", item)
		}
	}
}

// humanPriority translates the ranked action into the label used by dashboard readers.
func humanPriority(a blast.Action) string {
	if a.Lane == blast.LaneVerify {
		return "Verify"
	}
	switch a.HighestTierReduced {
	case blast.P1:
		return "Urgent"
	case blast.P2:
		return "High"
	case blast.P3:
		return "Medium"
	case blast.P4, blast.P5:
		return "Low"
	default:
		return "Optional"
	}
}

// printBlast summarizes the ranked changes in each lane.
func printBlast(w io.Writer, r blast.Report) {
	fmt.Fprintln(w, "Network exposure review")
	var top []blast.Action
	for _, a := range r.Actions {
		if a.HighestTierReduced == "" {
			continue
		}
		top = append(top, a)
		if len(top) == 3 {
			break
		}
	}
	if len(top) > 0 {
		fmt.Fprintln(w, "\nHighest-impact changes")
		for _, a := range top {
			hp := ""
			if a.HighProfile {
				hp = " [frequently targeted]"
			}
			if len(a.Benefits) > 0 {
				fmt.Fprintf(w, "  %-6s  %s%s (helps protect %s)\n", humanPriority(a), a.Title, hp, strings.Join(a.Benefits, ", "))
			} else {
				fmt.Fprintf(w, "  %-6s  %s%s\n", humanPriority(a), a.Title, hp)
			}
		}
	}
	for _, group := range []struct {
		lane blast.Lane
		name string
	}{{blast.LaneFixNow, "Fix now"}, {blast.LaneReduceExposure, "Reduce exposure"}, {blast.LaneVerify, "Verify"}} {
		fmt.Fprintf(w, "\n%s\n", group.name)
		n := 0
		for _, a := range r.Actions {
			if a.Lane != group.lane {
				continue
			}
			n++
			if n > 5 {
				continue
			}
			fmt.Fprintf(w, "  [%s] %s", humanPriority(a), a.Title)
			if a.HighProfile {
				fmt.Fprint(w, " [frequently targeted]")
			}
			if len(a.Benefits) > 0 {
				fmt.Fprintf(w, " (%s)", strings.Join(a.Benefits, ", "))
			}
			fmt.Fprintf(w, "\n    %s\n", a.Reason)
			if len(a.BreaksApproved) > 0 {
				fmt.Fprintf(w, "    Note: would interrupt approved path(s): %s.\n", strings.Join(a.BreaksApproved, ", "))
			}
		}
		if n == 0 {
			fmt.Fprintln(w, "  None.")
		} else if n > 5 {
			fmt.Fprintf(w, "  ...and %d more (run with -json to inspect all).\n", n-5)
		}
	}
	fmt.Fprintln(w, "\nDevice internet access")
	if len(r.Cloud) == 0 {
		fmt.Fprintln(w, "  No clients found.")
	}
	for _, c := range r.Cloud {
		fmt.Fprintf(w, "  %s: %s - %s\n", c.Name, c.State, c.Reason)
	}
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
	if err := verifyStatePathWritable(cfg.State.Path); err != nil {
		return fmt.Errorf("state path %q is not writable (set state.path to a writable file): %w", cfg.State.Path, err)
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
	if !cfg.State.ExplicitPath {
		if err := checkLegacyCWDState(logger, cfg.State.Path); err != nil {
			return err
		}
	}
	logger.Info("starting uniblue watch",
		"site", cfg.UniFi.Site,
		"interval", cfg.Scan.Interval,
		"checks", len(checkList),
		"state_path", cfg.State.Path,
	)

	var session *watchSession
	session = &watchSession{
		cfg:    cfg,
		minSev: minSev,
		logger: logger,
		scanFn: func(ctx context.Context) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
			return executeCycleWithPrev(ctx, cfg, checkList, session.lastSnap, session.prevState)
		},
		sendFn:       notifier.Send,
		sendWithIDFn: notifier.SendWithID,
		loadFn:       risk.LoadState,
		saveFn:       risk.SaveState,
	}

	// Run one pass immediately, then repeat on a ticker until cancelled.
	session.runCycle(ctx)

	ticker := time.NewTicker(cfg.Scan.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("stopping uniblue watch")
			return nil
		case <-ticker.C:
			session.runCycle(ctx)
		}
	}
}

// watchSession holds in-memory baseline state across `uniblue watch` cycles so
// a runtime SaveState failure (such as a read-only remount or full disk) never
// reloads stale on-disk state and re-sends identical alerts on every interval,
// and transient controller telemetry outages preserve last-known settings,
// WLANs, and switch port profiles without dropping posture findings.
type watchSession struct {
	cfg               *config.Config
	minSev            checks.Severity
	logger            *slog.Logger
	prevState         *risk.State
	lastSnap          *unifi.Snapshot
	stateLoaded       bool
	pendingWebhookID  string
	pendingWebhookKey string
	pendingDiff       risk.Diff

	scanFn       func(ctx context.Context) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error)
	sendFn       func(ctx context.Context, site string, diff risk.Diff) error
	sendWithIDFn func(ctx context.Context, id, site string, diff risk.Diff) error
	loadFn       func(path string) (*risk.State, error)
	saveFn       func(path string, st *risk.State) error
}

// watchDiffFingerprint derives a stable SHA-256 identity from the alert-bearing
// entries in diff, excluding volatile client telemetry (such as LastSeen or
// byte counters) so webhook retries reuse the original idempotent webhook-id.
func watchDiffFingerprint(site string, diff risk.Diff) string {
	var parts []string
	add := func(kind string, value any) {
		raw, _ := json.Marshal(value)
		parts = append(parts, kind+string(raw))
	}
	for _, f := range diff.NewFindings {
		add("new", []string{f.Key(), f.EffectiveSeverity.String()})
	}
	for _, f := range diff.EscalatedFindings {
		add("escalated", []string{f.Key(), f.EffectiveSeverity.String()})
	}
	for _, k := range diff.ResolvedKeys {
		add("resolved", k)
	}
	for _, c := range diff.NewTrustedClients {
		key := strings.ToLower(c.MAC)
		if key == "" {
			key = c.PrimaryIP()
		}
		add("trusted", []string{key, c.NetworkName})
	}
	for _, f := range diff.NewPortForwards {
		add("forward", f)
	}
	for _, c := range diff.NewCVEs {
		add("cve", c)
	}
	for _, e := range diff.Events {
		add("event", e)
	}
	sort.Strings(parts)
	raw, _ := json.Marshal(append([]string{site}, parts...))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (w *watchSession) runCycle(ctx context.Context) {
	if !w.stateLoaded {
		prev, err := w.loadFn(w.cfg.State.Path)
		if err != nil {
			w.logger.Error("failed to load previous state", "err", err)
			return
		}
		w.prevState = prev
		w.stateLoaded = true
	}

	snap, profiles, report, err := w.scanFn(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		w.logger.Error("scan cycle failed", "err", err)
		return
	}

	if preserveUnavailableWatchTelemetry(w.lastSnap, snap) {
		report = mergePreservedWatchPosture(snap, report, w.cfg.Network)
	}
	w.lastSnap = cloneWatchTelemetrySnapshot(snap)

	probedKeys := probedHostKeys(profiles)
	diff := risk.ComputeDiffWithProbed(w.prevState, snap, report, w.cfg.Network, probedKeys)
	w.logger.Info("scan cycle complete",
		"clients", report.ClientCount,
		"findings", len(report.Findings),
		"new", len(diff.NewFindings),
		"escalated", len(diff.EscalatedFindings),
		"resolved", len(diff.ResolvedKeys),
		"new_trusted_clients", len(diff.NewTrustedClients),
		"new_port_forwards", len(diff.NewPortForwards),
	)

	if diff.HasAlerts(w.minSev) {
		var sendErr error
		if w.sendWithIDFn != nil {
			fp := watchDiffFingerprint(snap.Site, diff)
			if w.pendingWebhookID == "" || fp == "" || w.pendingWebhookKey != fp {
				w.pendingWebhookID = notify.NewWebhookID()
				w.pendingWebhookKey = fp
				w.pendingDiff = diff
			}
			sendErr = w.sendWithIDFn(ctx, w.pendingWebhookID, snap.Site, w.pendingDiff)
		} else {
			sendErr = w.sendFn(ctx, snap.Site, diff)
		}
		if sendErr != nil {
			w.logger.Error("failed to send notification; preserving previous baseline for retry", "err", sendErr)
			return
		}
		w.pendingWebhookID = ""
		w.pendingWebhookKey = ""
		w.pendingDiff = risk.Diff{}
	} else {
		w.pendingWebhookID = ""
		w.pendingWebhookKey = ""
		w.pendingDiff = risk.Diff{}
	}

	nextState := risk.BuildStateWithPrev(w.prevState, snap, report, w.cfg.Network, probedKeys)
	// Always advance the in-memory baseline after notifications succeed so a
	// runtime persistence error does not trigger duplicate alerts every cycle.
	w.prevState = nextState
	if err := w.saveFn(w.cfg.State.Path, nextState); err != nil {
		w.logger.Error("failed to persist state; retaining updated baseline in memory", "path", w.cfg.State.Path, "err", err)
	}
}

// preserveUnavailableWatchTelemetry carries forward last-known SecuritySettings,
// WLANs, and profile-governed switch port fields when a watch cycle encounters
// a transient controller telemetry fetch error, returning true if snap was updated.
func preserveUnavailableWatchTelemetry(prevSnap, nextSnap *unifi.Snapshot) bool {
	if prevSnap == nil || nextSnap == nil || nextSnap.Visibility == nil {
		return false
	}
	changed := false
	if !nextSnap.Visibility.SettingsAvailable && nextSnap.SecuritySettings == nil && prevSnap.SecuritySettings != nil {
		cp := *prevSnap.SecuritySettings
		nextSnap.SecuritySettings = &cp
		changed = true
	}
	if !nextSnap.Visibility.WLANsAvailable && len(nextSnap.WLANs) == 0 && len(prevSnap.WLANs) > 0 {
		nextSnap.WLANs = append([]unifi.WLANConfig(nil), prevSnap.WLANs...)
		changed = true
	}
	if !nextSnap.Visibility.PortProfilesAvailable && len(prevSnap.Devices) > 0 && len(nextSnap.Devices) > 0 {
		prevPorts := make(map[string]unifi.SwitchPort)
		for _, d := range prevSnap.Devices {
			dmac := strings.ToLower(strings.TrimSpace(d.MAC))
			for _, p := range d.Ports {
				prevPorts[fmt.Sprintf("%s|%d", dmac, p.PortIdx)] = p
			}
		}
		for di := range nextSnap.Devices {
			dmac := strings.ToLower(strings.TrimSpace(nextSnap.Devices[di].MAC))
			for pi := range nextSnap.Devices[di].Ports {
				p := &nextSnap.Devices[di].Ports[pi]
				if old, ok := prevPorts[fmt.Sprintf("%s|%d", dmac, p.PortIdx)]; ok {
					if p.ProfileManaged {
						if p.Enabled != old.Enabled {
							p.Enabled = old.Enabled
							changed = true
						}
						if p.OpMode != old.OpMode {
							p.OpMode = old.OpMode
							changed = true
						}
						if p.Forward != old.Forward {
							p.Forward = old.Forward
							changed = true
						}
						if p.TaggedVLANMgmt != old.TaggedVLANMgmt {
							p.TaggedVLANMgmt = old.TaggedVLANMgmt
							changed = true
						}
						if p.NativeNetworkName != old.NativeNetworkName || p.NativeNetworkID != old.NativeNetworkID {
							p.NativeNetworkName = old.NativeNetworkName
							p.NativeNetworkID = old.NativeNetworkID
							changed = true
						}
						if p.PoEMode != old.PoEMode {
							p.PoEMode = old.PoEMode
							changed = true
						}
						if p.PortSecurityEnabled != old.PortSecurityEnabled {
							p.PortSecurityEnabled = old.PortSecurityEnabled
							changed = true
						}
						if len(p.PortSecurityMACs) == 0 && len(old.PortSecurityMACs) > 0 {
							p.PortSecurityMACs = append([]string(nil), old.PortSecurityMACs...)
							changed = true
						}

						if p.PortConfID == "" && old.PortConfID != "" {
							p.PortConfID = old.PortConfID
						}
						continue
					}
					if p.OpMode == "" && old.OpMode != "" {
						p.OpMode = old.OpMode
						changed = true
					}
					if p.Forward == "" && old.Forward != "" {
						p.Forward = old.Forward
						changed = true
					}
					if p.TaggedVLANMgmt == "" && old.TaggedVLANMgmt != "" {
						p.TaggedVLANMgmt = old.TaggedVLANMgmt
						changed = true
					}
					if p.NativeNetworkName == "" && old.NativeNetworkName != "" {
						p.NativeNetworkName = old.NativeNetworkName
						if p.NativeNetworkID == "" {
							p.NativeNetworkID = old.NativeNetworkID
						}
						changed = true
					}
				}
			}
		}
	}
	return changed
}

func cloneWatchTelemetrySnapshot(snap *unifi.Snapshot) *unifi.Snapshot {
	if snap == nil {
		return nil
	}
	cp := &unifi.Snapshot{
		Site: snap.Site,
	}
	if snap.SecuritySettings != nil {
		sec := *snap.SecuritySettings
		sec.HoneypotIPs = append([]string(nil), snap.SecuritySettings.HoneypotIPs...)
		cp.SecuritySettings = &sec
	}
	if len(snap.WLANs) > 0 {
		cp.WLANs = append([]unifi.WLANConfig(nil), snap.WLANs...)
	}
	if len(snap.Devices) > 0 {
		cp.Devices = make([]unifi.Device, len(snap.Devices))
		for i, d := range snap.Devices {
			cp.Devices[i] = d
			if len(d.Ports) > 0 {
				cp.Devices[i].Ports = make([]unifi.SwitchPort, len(d.Ports))
				copy(cp.Devices[i].Ports, d.Ports)
			}
		}
	}
	return cp
}

func watchFindingKey(f checks.Finding) string {
	host := strings.ToLower(strings.TrimSpace(f.Client.MAC))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(f.Client.PrimaryIP()))
	}
	return fmt.Sprintf("%s|%s|%d|%s", f.CheckID, host, f.Port, f.Property)
}

func mergePreservedWatchPosture(snap *unifi.Snapshot, report risk.Report, netCfg config.NetworkConfig) risk.Report {
	eval := risk.Evaluate(snap, nil, netCfg)
	seen := make(map[string]struct{}, len(report.Findings))
	for _, f := range report.Findings {
		seen[watchFindingKey(f)] = struct{}{}
	}
	for _, f := range eval.Findings {
		if _, ok := seen[watchFindingKey(f)]; !ok {
			report.Findings = append(report.Findings, f)
			seen[watchFindingKey(f)] = struct{}{}
		}
	}
	report.UniFiPosture = eval.UniFiPosture
	report.SwitchPorts = eval.SwitchPorts
	report.PostureNotes = eval.PostureNotes
	return report
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
		fp := newSiteFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet(), snap)
		fp.SetHostPortHints(snap.PortHintsByIP())
		profiles = fp.FingerprintAll(ctx, snap.Clients)
	} else {
		// Create stub profiles for configured bridge/flow enrichment even without active probing.
		profiles = make([]probe.HostProfile, len(snap.Clients))
		for i, cl := range snap.Clients {
			profiles[i] = probe.HostProfile{Client: cl}
		}
	}
	enrichSiteAndProfiles(snap, profiles, cfg.Network)

	ouiDB := oui.New("")
	_ = ouiDB.Load()
	classifier, err := classify.Load(classifydata.BuiltinFS, ouiDB)
	if err != nil {
		return err
	}
	classes := classifier.ClassifyAll(snap, profiles)

	if *jsonOut {
		return writeJSON(stdout, map[string]any{
			"snapshot":         snap,
			"profiles":         profiles,
			"service_coverage": probe.ComputeServiceCoverage(profiles),
			"classifications":  classes,
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
	hostname := fs.String("hostname", "", "optional target hostname for hostname-gated checks")
	mac := fs.String("mac", "", "optional target MAC address for MAC/OUI-gated checks")
	ouiVendor := fs.String("oui", "", "optional target hardware OUI vendor string for oui_contains checks")
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

	// Build a port list covering every precondition port (PortsAny, PortsAll,
	// Probe.Port) across the selected checks plus UniBlue's default ports.
	portSet := make(map[int]struct{})
	for _, p := range config.DefaultPorts {
		portSet[p] = struct{}{}
	}
	for _, chk := range list {
		for _, p := range chk.Preconditions.PortsAny {
			portSet[p] = struct{}{}
		}
		for _, p := range chk.Preconditions.PortsAll {
			portSet[p] = struct{}{}
		}
		if chk.Probe.Port > 0 {
			portSet[chk.Probe.Port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}

	targetCl := buildCheckTestClient(*target, *hostname, *mac, *ouiVendor)
	fp := probe.NewFingerprinter(ports, 1, *timeout, nil)
	// Keep single-target `check test` strictly scoped to the target IP: inject
	// an empty discovery snapshot so FingerprintAll still runs TCP/HTTP/SSH and
	// Nerva protocol fingerprinting on the target without broadcasting LAN-wide
	// mDNS/SSDP/WSD sweeps or sending UPnP HTTP GETs to unrelated LAN hosts.
	fp.SetCachedDiscovery(&probe.LANDiscovery{})
	profiles := fp.FingerprintAll(ctx, []unifi.Client{targetCl})
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Fprintf(stderr, "Warning: target %q was refused by the local-IP probe guard (must be a private, ULA, CGNAT, link-local, or loopback IP address).\n", targetCl.IP)
		return fmt.Errorf("check test: target %q is not an allowed local/private IP address", targetCl.IP)
	}
	profile := profiles[0]

	fmt.Fprintf(stdout, "Target: %s | Open ports: %v\n", *target, profile.OpenPorts)
	for port, banner := range profile.HTTP {
		fmt.Fprintf(stdout, "  HTTP(%d): status=%d server=%q title=%q\n", port, banner.StatusCode, banner.Server, banner.Title)
	}

	runner := checks.NewRunner(list, 1)
	findings := runner.RunHost(ctx, profile)
	if err := ctx.Err(); err != nil {
		return err
	}
	singleCheck := *checkID != "" && len(list) == 1
	if len(findings) == 0 {
		fmt.Fprintln(stdout, "No findings matched.")
		reportUnevaluableCheckHints(stderr, list, targetCl, singleCheck)
		return nil
	}
	for _, f := range findings {
		fmt.Fprintf(stdout, "[%s] %s (%s) on port %d: %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), f.CheckID, f.Title, f.Port, f.Evidence)
	}
	if !singleCheck {
		reportUnevaluableCheckHints(stderr, list, targetCl, false)
	}
	return nil
}

// buildCheckTestClient constructs the target Client for `check test`, resolving
// hardware OUI vendor metadata from the local IEEE/built-in OUI database when
// -mac is supplied so oui_contains preconditions can be evaluated.
func buildCheckTestClient(target, hostname, mac, ouiOverride string) unifi.Client {
	cl := unifi.Client{
		IP:       strings.TrimSpace(target),
		Hostname: strings.TrimSpace(hostname),
		MAC:      config.CanonicalMAC(mac),
		OUI:      strings.TrimSpace(ouiOverride),
	}
	if cl.OUI == "" && cl.MAC != "" {
		ouiDB := oui.New("")
		_ = ouiDB.Load()
		cl.OUI = ouiDB.Lookup(cl.MAC).Vendor
	}
	return cl
}

// reportUnevaluableCheckHints writes concise stderr guidance whenever selected
// checks require metadata (hostname, MAC, OUI, or LAN multicast discovery) that
// is unavailable in the current single-target `check test` invocation.
func reportUnevaluableCheckHints(stderr io.Writer, list []*checks.Check, target unifi.Client, singleCheck bool) {
	var needHostname, needMAC, needOUI, needDiscovery int
	for _, chk := range list {
		if chk.Preconditions.HostnameRegex != "" && target.Hostname == "" {
			needHostname++
		}
		if len(chk.Preconditions.MACPrefix) > 0 && target.MAC == "" {
			needMAC++
		}
		if len(chk.Preconditions.OUIContains) > 0 && target.OUI == "" {
			needOUI++
		}
		if len(chk.Preconditions.MDNSTypeAny) > 0 ||
			chk.Preconditions.UPnPDeviceRegex != "" ||
			chk.Preconditions.UPnPServiceRegex != "" ||
			chk.Preconditions.WSTypeRegex != "" {
			needDiscovery++
		}
	}

	if singleCheck {
		if needHostname > 0 {
			fmt.Fprintln(stderr, "Note: this check requires hostname_regex; pass -hostname <name> to evaluate it.")
		}
		if needMAC > 0 {
			fmt.Fprintln(stderr, "Note: this check requires mac_prefix; pass -mac <mac> to evaluate it.")
		}
		if needOUI > 0 {
			if target.MAC == "" {
				fmt.Fprintln(stderr, "Note: this check requires oui_contains; pass -mac <mac> (with synced OUI cache) or -oui <vendor> to evaluate it.")
			} else {
				fmt.Fprintln(stderr, "Note: this check requires oui_contains, but no OUI vendor was resolved for -mac; run `uniblue oui sync` or pass -oui <vendor>.")
			}
		}
		if needDiscovery > 0 {
			fmt.Fprintln(stderr, "Note: this check requires LAN multicast discovery (mDNS/UPnP/WS-Discovery), which single-target `check test` does not broadcast.")
		}
		return
	}

	var notes []string
	if needHostname > 0 {
		notes = append(notes, fmt.Sprintf("%d hostname-gated (pass -hostname <name>)", needHostname))
	}
	if needMAC > 0 {
		notes = append(notes, fmt.Sprintf("%d MAC-gated (pass -mac <mac>)", needMAC))
	}
	if needOUI > 0 {
		notes = append(notes, fmt.Sprintf("%d OUI-gated (pass -mac <mac> or -oui <vendor>)", needOUI))
	}
	if needDiscovery > 0 {
		notes = append(notes, fmt.Sprintf("%d LAN-discovery-gated (mDNS/UPnP/WS-Discovery skipped in single-target mode)", needDiscovery))
	}
	if len(notes) > 0 {
		fmt.Fprintf(stderr, "Note: unevaluable checks skipped due to missing metadata: %s.\n", strings.Join(notes, "; "))
	}
}

// executeCycle runs one end-to-end UniFi snapshot, host fingerprinting pass,
// declarative check sweep, and blast-radius risk evaluation.
func executeCycle(ctx context.Context, cfg *config.Config, checkList []*checks.Check) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
	prev, _ := risk.LoadState(cfg.State.Path)
	return executeCycleWithPrev(ctx, cfg, checkList, nil, prev)
}

// watchAuditedSSHHostKeys caches opt-in SSH key audit outcomes for unchanged
// host keys during this process so periodic watch scans replay findings without
// sending repeat PK_OK queries.
var watchAuditedSSHHostKeys = map[string]probe.SSHKeyAuditCacheEntry{}

func executeCycleWithPrev(ctx context.Context, cfg *config.Config, checkList []*checks.Check, prevSnap *unifi.Snapshot, prev *risk.State) (*unifi.Snapshot, []probe.HostProfile, risk.Report, error) {
	snap, profiles, _, _, report, err := executeCycleDetailed(ctx, cfg, checkList, prevSnap, prev)
	return snap, profiles, report, err
}

func executeCycleDetailed(ctx context.Context, cfg *config.Config, checkList []*checks.Check, prevSnap *unifi.Snapshot, prev *risk.State) (*unifi.Snapshot, []probe.HostProfile, []checks.Finding, map[string][]probe.ChildDevice, risk.Report, error) {
	if prev == nil {
		prev, _ = risk.LoadState(cfg.State.Path)
	}
	ctrl, err := unifi.New(cfg.UniFi)
	if err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}
	if err := ctrl.Login(ctx); err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}
	snap, err := ctrl.FetchSnapshot(ctx)
	if err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}
	preserveUnavailableWatchTelemetry(prevSnap, snap)

	// Union configured default ports with any specialty ports required by loaded
	// community checks so dropping a YAML check into checks/ works automatically.
	scanPorts := mergePorts(cfg.Scan.Ports, checkList)

	fp := newSiteFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet(), snap)
	if err := fp.SetSSHKeyAudit(cfg.Scan.SSHKeyAudit); err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}
	if prev != nil {
		fp.SetPreviousSSHHostKeys(prev.SSHHostKeys)
	}
	fp.SetAuditedSSHHostKeys(watchAuditedSSHHostKeys)
	// Seed per-host port hints from UniFi port forwards, firewall policies, and
	// identity-gated checks (MAC/hostname) so specialty ports are only dialed on
	// matching hosts instead of every host on the LAN.
	fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, checkList, snap.PortHintsByIP()))
	profiles := fp.FingerprintAll(ctx, snap.Clients)
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}

	// Attach owner-supplied site supplement, bridge/NVR inventories, and passive
	// service/flow records through the same helper used across all CLI modes.
	devChildren := enrichSiteAndProfiles(snap, profiles, cfg.Network)

	runner := checks.NewRunner(checkList, cfg.Scan.Concurrency)
	rawFindings := runner.RunAll(ctx, profiles)
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, risk.Report{}, err
	}

	// Merge noise-filtered Nerva protocol findings (e.g., legacy protocols,
	// anonymous service access, expired TLS certs) so they receive UniFi
	// blast-radius scoring, state diffing, and watch alerting alongside YAML checks.
	keys := prev.CompareSSHHostKeys(profiles)
	rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)

	report := risk.Evaluate(snap, rawFindings, cfg.Network)
	report.SSHHostKeys = keys
	return snap, profiles, rawFindings, devChildren, report, nil
}

// siteSubnets parses all configured IPv4 and IPv6 network prefixes from snap so
// CLI scans permit probing hosts on routed public LAN blocks and site IPv6 GUAs.
func siteSubnets(snap *unifi.Snapshot) []netip.Prefix {
	if snap == nil {
		return nil
	}
	var out []netip.Prefix
	for _, n := range snap.Networks {
		if p, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil {
			out = append(out, p.Masked())
		}
		if p, err := netip.ParsePrefix(strings.TrimSpace(n.IPv6Subnet)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// siteGatewayReflectorIPs collects UniFi gateway LAN interface IPs so passive
// mDNS discovery distinguishes legitimate gateway-reflected cross-VLAN services
// from third-party LAN spoofing.
func siteGatewayReflectorIPs(snap *unifi.Snapshot) []string {
	if snap == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return
		}
		norm := addr.Unmap().String()
		if _, dup := seen[norm]; dup {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	for _, d := range snap.Devices {
		t := strings.ToLower(strings.TrimSpace(d.Type))
		if t == "ugw" || t == "udm" || t == "uxg" || t == "ucg" {
			add(d.IP)
		}
	}
	for _, n := range snap.Networks {
		p := strings.ToLower(strings.TrimSpace(n.Purpose))
		if p == "wan" || p == "wan2" {
			continue
		}
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet)); err == nil {
			if pfx.Addr().IsValid() && pfx.Addr() != pfx.Masked().Addr() {
				add(pfx.Addr().String())
			}
		}
	}
	return out
}

// newSiteFingerprinter constructs a Fingerprinter pre-populated with all site
// IPv4/IPv6 subnets and gateway mDNS reflector IPs from snap.
func newSiteFingerprinter(ports []int, concurrency int, timeout time.Duration, excluded map[string]struct{}, snap *unifi.Snapshot) *probe.Fingerprinter {
	fp := probe.NewFingerprinter(ports, concurrency, timeout, excluded)
	if snap != nil {
		fp.SetInfrastructure(snap.Devices)
	}
	fp.SetAllowedSubnets(siteSubnets(snap))
	fp.SetTrustedReflectors(siteGatewayReflectorIPs(snap))
	return fp
}

// checkLegacyCWDState fails fast when the resolved state.path does not exist
// yet while a legacy ./uniblue-state.json exists in the current working
// directory at a different location, preventing an upgrade from silently
// creating an empty baseline and firing a full re-alert storm.
func checkLegacyCWDState(logger *slog.Logger, resolvedPath string) error {
	legacyAbs, found := detectLegacyCWDState(resolvedPath)
	if !found {
		return nil
	}
	if logger != nil {
		logger.Warn("configured state file does not exist yet while a legacy state file exists in the current working directory; move it or set state.path explicitly to preserve baseline history",
			"state_path", resolvedPath,
			"legacy_cwd_state", legacyAbs,
		)
	}
	return fmt.Errorf("state path %q does not exist yet while legacy state file %q exists in the current working directory (move it to %q or set state.path explicitly to avoid re-alerting existing findings)", resolvedPath, legacyAbs, resolvedPath)
}

// warnLegacyCWDState emits a warning when a legacy ./uniblue-state.json exists
// at a different location than resolvedPath.
func warnLegacyCWDState(logger *slog.Logger, resolvedPath string) {
	legacyAbs, found := detectLegacyCWDState(resolvedPath)
	if !found || logger == nil {
		return
	}
	logger.Warn("configured state file does not exist yet while a legacy state file exists in the current working directory; set state.path explicitly or move it to preserve baseline history",
		"state_path", resolvedPath,
		"legacy_cwd_state", legacyAbs,
	)
}

// detectLegacyCWDState reports whether resolvedPath targets the default
// uniblue-state.json filename at a non-existent location while a legacy
// ./uniblue-state.json file exists in the current working directory.
func detectLegacyCWDState(resolvedPath string) (string, bool) {
	if filepath.Base(resolvedPath) != "uniblue-state.json" {
		return "", false
	}
	if _, err := os.Stat(resolvedPath); err == nil {
		return "", false
	}
	legacy := "uniblue-state.json"
	if _, err := os.Stat(legacy); err != nil {
		return "", false
	}
	absResolved, err1 := filepath.Abs(resolvedPath)
	absLegacy, err2 := filepath.Abs(legacy)
	if err1 == nil && err2 == nil && absResolved == absLegacy {
		return "", false
	}
	return absLegacy, true
}

// verifyStatePathWritable creates parent directories if needed and writes+removes
// a tiny probe file so unwritable state paths fail fast at startup instead of
// silently causing repeated alert storms every watch interval.
func verifyStatePathWritable(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".uniblue-write-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

func probedHostKeys(profiles []probe.HostProfile) map[string]struct{} {
	out := make(map[string]struct{}, len(profiles)*2)
	for _, hp := range profiles {
		if m := strings.ToLower(strings.TrimSpace(hp.Client.MAC)); m != "" {
			out[m] = struct{}{}
		}
		for _, ip := range hp.Client.AllIPs() {
			out[strings.ToLower(strings.TrimSpace(ip))] = struct{}{}
		}
	}
	return out
}

// enrichSiteAndProfiles merges owner-supplied site supplements (switch ACLs,
// proxy routes, tunnels, dynamic NAT mappings, backups), bridge/NVR child
// inventories, and passive service/flow observations onto snap and profiles.
// It returns child devices matched to UniFi infrastructure devices (e.g., UDM
// Pro or UNVR running UniFi Protect) keyed by lowercase device MAC so offline
// exports render identical enrolled children to the live dashboard.
// Load errors are surfaced in snap.Visibility.MissingFeeds rather than ignored.
func enrichSiteAndProfiles(snap *unifi.Snapshot, profiles []probe.HostProfile, netCfg config.NetworkConfig) map[string][]probe.ChildDevice {
	if snap != nil && strings.TrimSpace(netCfg.SiteSupplementPath) != "" {
		_ = unifi.ApplySiteSupplement(snap, netCfg.SiteSupplementPath)
	}
	var devChildren map[string][]probe.ChildDevice
	for _, bi := range netCfg.BridgeInventories {
		if strings.TrimSpace(bi.Path) == "" {
			continue
		}
		children, err := probe.LoadBridgeInventory(probe.BridgeInventorySpec{
			Format:       bi.Format,
			Path:         bi.Path,
			ParentIP:     bi.ParentIP,
			ParentMAC:    bi.ParentMAC,
			ParentRole:   bi.ParentRole,
			ObservedFrom: bi.ObservedFrom,
		})
		if err != nil {
			unifi.RecordMissingFeed(snap, fmt.Sprintf("bridge-inventory (%s: %v)", bi.Path, err))
			continue
		}
		if len(children) > 0 {
			probe.AttachBridgeChildren(profiles, children)
			if snap != nil && len(snap.Devices) > 0 {
				for mac, list := range probe.MatchDeviceBridgeChildren(snap.Devices, children) {
					if devChildren == nil {
						devChildren = make(map[string][]probe.ChildDevice)
					}
					for _, ch := range list {
						dup := false
						for _, ex := range devChildren[mac] {
							if ex.ID == ch.ID {
								dup = true
								break
							}
						}
						if !dup {
							devChildren[mac] = append(devChildren[mac], ch)
						}
					}
				}
			}
		}
	}
	if strings.TrimSpace(netCfg.PassiveFlowsPath) != "" {
		flows, err := probe.LoadPassiveFlows(netCfg.PassiveFlowsPath)
		if err != nil {
			unifi.RecordMissingFeed(snap, fmt.Sprintf("passive-flows (%s: %v)", netCfg.PassiveFlowsPath, err))
		} else if len(flows) > 0 {
			probe.ApplyPassiveFlows(profiles, flows)
		}
	}
	return devChildren
}

// localCVEMatchesAndSignals returns endpoint-bound CVE matches alongside
// high-confidence target velocity signals from the local cache.
func localCVEMatchesAndSignals(cfg *config.Config, snap *unifi.Snapshot, profiles []probe.HostProfile) ([]cve.Match, []blast.TargetSignal, error) {
	cache := cve.NewCache(cfg.CVE.CacheDir)
	if _, err := cache.Stats(); err != nil {
		return nil, nil, err
	}
	identifier, err := cve.LoadFingerprinter(fingerprints.BuiltinFS)
	if err != nil {
		return nil, nil, err
	}
	products := identifier.Identify(snap, profiles)
	matches, err := cache.MatchProducts(products, cve.MatchOptions{
		MinSeverity:          checks.SeverityHigh,
		PotentialMaxAgeYears: 2,
	})
	if err != nil {
		return nil, nil, err
	}
	signals := server.CollectTargetSignals(cache, products, time.Now().UTC())
	return matches, signals, nil
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

// printActionQueueSummary prints a concise 3-lane action queue overview at the
// top of `uniblue scan` while keeping all detailed check sections intact below.
func printActionQueueSummary(w io.Writer, r blast.Report) {
	fmt.Fprintln(w, "0. Recommended Action Queue (highest-impact changes first):")
	for _, group := range []struct {
		lane  blast.Lane
		title string
	}{
		{blast.LaneFixNow, "Fix now"},
		{blast.LaneReduceExposure, "Reduce exposure"},
		{blast.LaneVerify, "Verify"},
	} {
		var items []blast.Action
		for _, a := range r.Actions {
			if a.Lane == group.lane {
				items = append(items, a)
			}
		}
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s (%d):\n", group.title, len(items))
		for _, a := range items[:min(5, len(items))] {
			prefix := "[" + humanPriority(a) + "]"
			extra := ""
			if len(a.Benefits) > 0 {
				extra = " (" + strings.Join(a.Benefits, ", ") + ")"
			}
			if a.HighProfile {
				extra += " [frequently targeted]"
			}
			fmt.Fprintf(w, "    %s %s%s\n", prefix, a.Title, extra)
			if len(a.BreaksApproved) > 0 {
				fmt.Fprintf(w, "      Note: would interrupt approved path(s): %s.\n", strings.Join(a.BreaksApproved, ", "))
			}
		}
		if len(items) > 5 {
			fmt.Fprintf(w, "    ...and %d more (run `uniblue blast -json` to inspect all).\n", len(items)-5)
		}
	}
}

// printReport renders a unified, operator-ready security summary combining
// the 3-lane counterfactual action queue, confirmed live check findings,
// exact-version CVE rollups, classified WAN exposure, version-unknown patch
// checks, and clean-posture statistics.
func printReport(w io.Writer, snap *unifi.Snapshot, report risk.Report, blastRep *blast.Report, profiles []probe.HostProfile, exactCVEs, potentialCVEs []cve.ProductSummary, cveLoaded bool) {
	fmt.Fprintf(w, "UniBlue Security Summary | Site: %s (%s) | Clients: %d | UniFi Gear: %d | Networks: %d\n\n",
		snap.Site, snap.ControllerType, report.ClientCount, report.UniFiDeviceCount, len(snap.Networks))

	if blastRep != nil && len(blastRep.Actions) > 0 {
		printActionQueueSummary(w, *blastRep)
		fmt.Fprintln(w)
	}

	// 1. Confirmed Actionable LAN Findings (active checks + exact-version CVEs).
	var activeChecks []checks.Finding
	var firmwareFindings []checks.Finding
	for _, f := range report.Findings {
		if f.IsInventoryOnly() {
			continue
		}
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

	// 3. Rolled-up Patch Verification Reminders.
	if cveLoaded && len(potentialCVEs) > 0 {
		fmt.Fprintf(w, "\n3. Patch Verification (%d product(s)):\n", len(potentialCVEs))
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
		fmt.Fprintf(w, "  - [LOW] %s: %s\n", f.Title, f.Evidence)
	}
	fmt.Fprintf(w, "  - [OK] UniFi Infrastructure: %d/%d device(s) up to date\n", report.CleanUniFiDevices, report.UniFiDeviceCount)
	probedCount := len(profiles)
	skippedCount := report.ClientCount - probedCount
	if skippedCount < 0 {
		skippedCount = 0
	}
	if skippedCount > 0 {
		cleanProbed := countCleanProbedHosts(profiles, report.Findings)
		fmt.Fprintf(w, "  - [OK] LAN Clients:          %d/%d probed host(s) passed (%d skipped/excluded)\n", cleanProbed, probedCount, skippedCount)
	} else {
		fmt.Fprintf(w, "  - [OK] LAN Clients:          %d/%d active host(s) passed with zero unauthenticated services exposed\n", report.CleanClients, report.ClientCount)
	}
	if !cveLoaded {
		fmt.Fprintln(w, "  - [TIP] Run `uniblue cve sync` once to include offline NVD+KEV correlation in `uniblue scan`.")
	}
}

// countCleanProbedHosts counts how many actually probed hosts in profiles have
// zero non-inventory findings in findings, avoiding distortion when skipped or
// excluded hosts carry UniFi-derived findings such as WAN port forwards.
func countCleanProbedHosts(profiles []probe.HostProfile, findings []checks.Finding) int {
	affectedIPs := make(map[string]struct{})
	affectedMACs := make(map[string]struct{})
	for _, f := range findings {
		if f.IsInventoryOnly() {
			continue
		}
		for _, ip := range f.Client.AllIPs() {
			affectedIPs[strings.ToLower(strings.TrimSpace(ip))] = struct{}{}
		}
		if m := strings.ToLower(strings.TrimSpace(f.Client.MAC)); m != "" && !strings.HasPrefix(m, "fw:") && !strings.HasPrefix(m, "gw:") {
			affectedMACs[m] = struct{}{}
		}
	}
	clean := 0
	for _, hp := range profiles {
		bad := false
		for _, ip := range hp.Client.AllIPs() {
			if _, ok := affectedIPs[strings.ToLower(strings.TrimSpace(ip))]; ok {
				bad = true
				break
			}
		}
		if !bad {
			if m := strings.ToLower(strings.TrimSpace(hp.Client.MAC)); m != "" {
				if _, ok := affectedMACs[m]; ok {
					bad = true
				}
			}
		}
		if !bad {
			clean++
		}
	}
	return clean
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
		key := cl.PrimaryIP()
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

// runCVE dispatches `uniblue cve <sync|explore|search|show|history>` subcommands.
func runCVE(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: uniblue cve <sync|explore|search|show|history> [flags]")
	}
	switch args[0] {
	case "sync":
		return runCVESync(ctx, args[1:], stdout, stderr)
	case "explore":
		return runCVEExplore(ctx, args[1:], stdout, stderr)
	case "history":
		return runCVEHistory(args[1:], stdout, stderr)
	case "search":
		return runCVESearch(ctx, args[1:], stdout, stderr)
	case "show":
		return runCVEShow(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown cve subcommand %q (want sync, explore, search, show, or history)", args[0])
	}
}

// flagPassed reports whether the named flag was explicitly supplied on the
// command line to fs.
func flagPassed(fs *flag.FlagSet, name string) bool {
	passed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}

// resolveCVECacheDir resolves the local CVE cache directory, honoring an
// explicit -cache flag first, then cve.cache_dir from config.yaml (parsed
// without requiring UniFi credentials or validating unrelated fields), and
// finally cve.DefaultCacheDir(). If configExplicit is true and cfgPath cannot
// be read or parsed, an error is returned instead of silently falling back.
func resolveCVECacheDir(flagDir, cfgPath string, configExplicit bool) (string, error) {
	if strings.TrimSpace(flagDir) != "" {
		return strings.TrimSpace(flagDir), nil
	}
	if trimmed := strings.TrimSpace(cfgPath); trimmed != "" {
		raw, err := os.ReadFile(trimmed)
		if err != nil {
			if configExplicit || !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("read config %q: %w", trimmed, err)
			}
			return cve.DefaultCacheDir(), nil
		}
		var partial struct {
			CVE struct {
				CacheDir string `yaml:"cache_dir"`
			} `yaml:"cve"`
		}
		if err := yaml.Unmarshal(raw, &partial); err != nil {
			return "", fmt.Errorf("parse config %q: %w", trimmed, err)
		}
		if dir := strings.TrimSpace(partial.CVE.CacheDir); dir != "" {
			return dir, nil
		}
	}
	return cve.DefaultCacheDir(), nil
}

// runCVESync downloads CISA KEV and NVD JSON 2.0 yearly feeds into the local
// vendor-sharded cache and prints storage and timing metrics.
func runCVESync(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve sync", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "optional UniBlue YAML config file (used for cve.cache_dir)")
	cacheDir := fs.String("cache", "", "local CVE cache directory (overrides config)")
	since := fs.Int("since", 2002, "earliest NVD year to download (2002 = full database)")
	force := fs.Bool("force", false, "re-download and re-index even if feeds are unchanged")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolvedDir, err := resolveCVECacheDir(*cacheDir, *cfgPath, flagPassed(fs, "config"))
	if err != nil {
		return err
	}
	cache := cve.NewCache(resolvedDir)
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
	if *limit < 0 {
		return fmt.Errorf("cve explore: -limit must be >= 0 (got %d)", *limit)
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

	fp := newSiteFingerprinter(cfg.Scan.Ports, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet(), snap)
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

	var exact, ambiguous, potential []cve.Match
	for _, m := range matches {
		switch m.Confidence {
		case cve.ConfidenceExact:
			exact = append(exact, m)
		case cve.ConfidenceVersionAmbiguous:
			ambiguous = append(ambiguous, m)
		default:
			potential = append(potential, m)
		}
	}

	fmt.Fprintf(stdout, "\nExact Version CVE Matches (%d):\n", len(exact))
	if len(exact) == 0 {
		fmt.Fprintln(stdout, "  None detected for observed exact versions.")
	} else {
		printCVEMatchTable(stdout, exact, len(exact))
	}

	if len(ambiguous) > 0 {
		fmt.Fprintf(stdout, "\nDistro-Packaged Software (Verify Backported Patches, %d):\n", len(ambiguous))
		printCVEMatchTable(stdout, ambiguous, len(ambiguous))
	}
	fmt.Fprintf(stdout, "\nPotential Product Matches (%d total, showing up to %d):\n", len(potential), *limit)
	if len(potential) == 0 {
		fmt.Fprintln(stdout, "  None.")
	} else {
		printCVEMatchTable(stdout, potential, *limit)
	}
	return nil
}

// runCVEHistory reports product-wide history using only the local cache.
func runCVEHistory(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve history", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "optional UniBlue config for cve.cache_dir")
	cacheDir := fs.String("cache", "", "local CVE cache directory (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var vendor, product string
	switch fs.NArg() {
	case 1:
		v, p, ok := strings.Cut(strings.TrimSpace(fs.Arg(0)), ":")
		if !ok {
			return errors.New("usage: uniblue cve history [-cache <dir>] <vendor> <product> (or <vendor>:<product>)")
		}
		vendor, product = strings.TrimSpace(v), strings.TrimSpace(p)
	case 2:
		vendor, product = strings.TrimSpace(fs.Arg(0)), strings.TrimSpace(fs.Arg(1))
	default:
		return errors.New("usage: uniblue cve history [-cache <dir>] <vendor> <product> (or <vendor>:<product>)")
	}
	if vendor == "" || product == "" || strings.ContainsAny(vendor+product, "*") {
		return errors.New("history requires a specific vendor and product")
	}
	dir, err := resolveCVECacheDir(*cacheDir, *cfgPath, flagPassed(fs, "config"))
	if err != nil {
		return err
	}
	h, err := cve.NewCache(dir).ProductVelocity(cve.Product{
		Vendors: []string{vendor}, Products: []string{product}, HighConfidence: true,
	}, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s:%s  %s\n", vendor, product, h.Class)
	fmt.Fprintf(stdout, "Historical CVEs: %d\nCISA KEV: %d", h.TotalCVEs, h.KEVCount)
	if h.LatestKEV != "" {
		fmt.Fprintf(stdout, " (latest addition %s)", h.LatestKEV)
	}
	fmt.Fprintf(stdout, ", %d linked to ransomware\n", h.RansomwareCount)
	for _, years := range []int{1, 3, 5} {
		count, covered := h.NetworkHigh[years]
		if covered {
			fmt.Fprintf(stdout, "%dy AV:N High/Critical: %d\n", years, count)
		} else {
			fmt.Fprintf(stdout, "%dy AV:N High/Critical: unavailable (incomplete coverage)\n", years)
		}
	}
	for _, year := range h.IncompleteYears {
		c := h.YearCoverage[year]
		if c.Total == 0 {
			fmt.Fprintf(stdout, "%s NVD CPE coverage unavailable\n", year)
		} else {
			fmt.Fprintf(stdout, "%s NVD CPE coverage %d/%d (%.1f%%, below 60%%)\n", year, c.WithCPE, c.Total, 100*float64(c.WithCPE)/float64(c.Total))
		}
	}
	return nil
}

// runCVESearch performs an offline search across the local CVE cache.
func runCVESearch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("cve search", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "config.yaml", "optional UniBlue YAML config file (used for cve.cache_dir)")
	cacheDir := fs.String("cache", "", "local CVE cache directory (overrides config)")
	vendor := fs.String("vendor", "", "restrict search to one CPE vendor shard")
	kevOnly := fs.Bool("kev", false, "show only CISA KEV actively exploited CVEs")
	minSevStr := fs.String("min-severity", "low", "minimum severity (info, low, medium, high, critical)")
	limit := fs.Int("limit", 30, "maximum number of results")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *limit < 0 {
		return fmt.Errorf("cve search: -limit must be >= 0 (got %d)", *limit)
	}

	minSev, err := checks.ParseSeverity(*minSevStr)
	if err != nil {
		return err
	}
	query := strings.Join(fs.Args(), " ")
	if query == "" && *vendor == "" && !*kevOnly {
		return errors.New("cve search requires a query, -vendor, or -kev")
	}

	resolvedDir, err := resolveCVECacheDir(*cacheDir, *cfgPath, flagPassed(fs, "config"))
	if err != nil {
		return err
	}
	cache := cve.NewCache(resolvedDir)
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
	cfgPath := fs.String("config", "config.yaml", "optional UniBlue YAML config file (used for cve.cache_dir)")
	cacheDir := fs.String("cache", "", "local CVE cache directory (overrides config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: uniblue cve show [-cache <dir>] <CVE-ID>")
	}

	resolvedDir, err := resolveCVECacheDir(*cacheDir, *cfgPath, flagPassed(fs, "config"))
	if err != nil {
		return err
	}
	cache := cve.NewCache(resolvedDir)
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
			bounds := formatCPERange(m)
			if m.NeedsContext {
				bounds += " (requires platform verification)"
			}
			fmt.Fprintf(stdout, "  - %s:%s %s\n", m.Vendor, m.Product, bounds)
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
	if maxRows < 0 {
		maxRows = 0
	}
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
	var devChildren map[string][]probe.ChildDevice
	checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
	if err != nil {
		return err
	}
	if !*noProbe {
		scanPorts := mergePorts(cfg.Scan.Ports, checkList)
		fp := newSiteFingerprinter(scanPorts, cfg.Scan.Concurrency, cfg.Scan.Timeout, cfg.Network.ExcludedSet(), snap)
		fp.SetHostPortHints(checks.PlanHostPorts(snap.Clients, checkList, snap.PortHintsByIP()))
		profiles = fp.FingerprintAll(ctx, snap.Clients)
		if err := ctx.Err(); err != nil {
			return err
		}
		devChildren = enrichSiteAndProfiles(snap, profiles, cfg.Network)
		runner := checks.NewRunner(checkList, cfg.Scan.Concurrency)
		rawFindings = runner.RunAll(ctx, profiles)
		if err := ctx.Err(); err != nil {
			return err
		}
		rawFindings = append(rawFindings, checks.FindingsFromProfiles(profiles, rawFindings)...)
	} else {
		profiles = make([]probe.HostProfile, len(snap.Clients))
		for i, cl := range snap.Clients {
			profiles[i] = probe.HostProfile{Client: cl}
		}
		devChildren = enrichSiteAndProfiles(snap, profiles, cfg.Network)
		var observeChecks []*checks.Check
		for _, c := range checkList {
			if c.Probe.Type == "observe" {
				observeChecks = append(observeChecks, c)
			}
		}
		runner := checks.NewRunner(observeChecks, cfg.Scan.Concurrency)
		rawFindings = runner.RunAll(ctx, profiles)
		if err := ctx.Err(); err != nil {
			return err
		}
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
		var exactCVEs, potentialCVEs []cve.ProductSummary
		var exportCVEs []cve.Match
		var exportSignals []blast.TargetSignal
		cveLoaded := false
		if matches, signals, err := localCVEMatchesAndSignals(cfg, snap, profiles); err == nil {
			cveLoaded = true
			exportCVEs, exportSignals = matches, signals
			for _, s := range cve.RollupMatches(matches) {
				if s.Confidence == cve.ConfidenceExact {
					exactCVEs = append(exactCVEs, s)
				} else {
					potentialCVEs = append(potentialCVEs, s)
				}
			}
		}

		profileByMAC := make(map[string]probe.HostProfile, len(profiles))
		for _, hp := range profiles {
			k := strings.ToLower(hp.Client.MAC)
			if k == "" {
				k = hp.Client.PrimaryIP()
			}
			profileByMAC[k] = hp
		}
		clientViews := make([]server.ClientView, 0, len(snap.Clients))
		for _, cl := range snap.Clients {
			k := strings.ToLower(cl.MAC)
			if k == "" {
				k = cl.PrimaryIP()
			}
			clsKey := cl.PrimaryIP()
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
				if !hp.ScannedAt.IsZero() {
					ts := hp.ScannedAt
					cv.LastScannedAt = &ts
				}
			}
			clientViews = append(clientViews, cv)
		}
		now := time.Now().UTC()
		viewModel := server.BuildPresentationModel(snap, report, model, clientViews, exactCVEs, potentialCVEs, profiles)
		server.AttachDeviceChildren(viewModel, devChildren)
		ctrlHost := ""
		if u, err := url.Parse(cfg.UniFi.URL); err == nil {
			ctrlHost = u.Hostname()
		}
		blastProfiles := server.AppendDeviceChildProfiles(snap, profiles, devChildren)
		blastRep, infraReps := server.EvaluateSiteBlast(snap, blastProfiles, rawFindings, report, cfg.Network, checkList, exportCVEs, exportSignals, ctrlHost)
		server.AttachBlast(viewModel, blastRep, infraReps)
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
			View:           viewModel,
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
	cveRefresh := fs.Duration("cve-refresh", 1*time.Hour, "background NVD+KEV CVE cache sync and refresh interval (0 to disable auto-sync)")
	noCVE := fs.Bool("no-cve", false, "skip local CVE cache correlation even if synced")
	demo := fs.Bool("demo", false, "serve built-in offline demo network (no UniFi controller needed)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *demo {
		return runDemo(ctx, []string{"-listen", *listen}, stdout, stderr)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := verifyStatePathWritable(cfg.State.Path); err != nil {
		return fmt.Errorf("state path %q is not writable (set state.path to a writable file): %w", cfg.State.Path, err)
	}
	checkList, err := loadAllChecks(cfg.Scan.ChecksDir)
	if err != nil {
		return err
	}
	scanPorts := mergePorts(cfg.Scan.Ports, checkList)

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	if !cfg.State.ExplicitPath {
		if err := checkLegacyCWDState(logger, cfg.State.Path); err != nil {
			return err
		}
	}
	eng, err := server.NewEngine(cfg, checkList, scanPorts, server.Options{
		ListenAddr:         *listen,
		PollInterval:       *poll,
		ReconcileInterval:  *reconcile,
		SkipCVE:            *noCVE,
		CVERefreshInterval: *cveRefresh,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	if err := eng.Start(ctx); err != nil {
		return err
	}
	return eng.Serve(ctx)
}

// runDemo serves UniBlue's web dashboard seeded with a realistic, completely
// offline synthetic UniFi network (or exports it as static HTML with -out) so
// operators and contributors can preview the UI or capture demo screenshots
// without connecting to a real UniFi controller.
func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address for the built-in demo web UI")
	outPath := fs.String("out", "", "optional path to export a self-contained static demo HTML file instead of serving")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	eng, err := server.NewDemoEngine(server.Options{
		ListenAddr: *listen,
		Logger:     logger,
	})
	if err != nil {
		return err
	}
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := server.RenderStaticHTML(f, eng.Snapshot()); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Wrote static UniBlue demo HTML to %s\n", *outPath)
		return nil
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
		fmt.Fprintf(w, "%s (%s · %s)%s | Uplink: %s | %d active, %d unused-open, %d disabled\n",
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
