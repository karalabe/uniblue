package topology

import (
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/karalabe/uniblue/internal/classify"
)

const (
	svgMargin   = 28
	svgColGap   = 18
	svgRowGap   = 22
	svgMaxCols  = 4
	svgRowH     = 42
	svgCardHead = 46
	svgSecHead  = 24
	svgCardPad  = 14
)

// RenderSVG writes a clean, self-contained, dynamically sized SVG topology
// diagram representing m to w. The layout adapts automatically to any number
// of UniFi VLANs, firewall zones, switches/APs, and active clients.
func RenderSVG(w io.Writer, m *Model) error {
	if m == nil {
		return fmt.Errorf("topology model is nil")
	}

	// Calculate total column cards (all VLANs plus an optional unused DMZ hint card).
	totalCards := len(m.VLANs)
	if m.HasUnusedDMZ {
		totalCards++
	}
	cols := totalCards
	if cols < 1 {
		cols = 1
	}
	if cols > svgMaxCols {
		cols = svgMaxCols
	}

	colW := 320
	if cols <= 2 {
		colW = 460
	} else if cols == 3 {
		colW = 390
	} else if cols == 4 {
		colW = 330
	}

	canvasW := svgMargin*2 + cols*colW + (cols-1)*svgColGap
	if canvasW < 1120 {
		canvasW = 1120
		colW = (canvasW - svgMargin*2 - (cols-1)*svgColGap) / cols
	}

	// Row 1 (WAN + Gateway + UniFi Infra) height scales with infra/WAN line count.
	topCardH := 134
	if need := 52 + len(m.Infra)*20; need > topCardH {
		topCardH = need
	}
	if need := 52 + len(m.WANRoutes)*20; need > topCardH {
		topCardH = need
	}
	topY := 72
	vlanStartY := topY + topCardH + 46

	// Compute dynamic height per VLAN row so cards never overflow or clip.
	type cardSlot struct {
		vlan *VLANGroup
		dmz  bool
	}
	slots := make([]cardSlot, 0, totalCards)
	for i := range m.VLANs {
		slots = append(slots, cardSlot{vlan: &m.VLANs[i]})
	}
	if m.HasUnusedDMZ {
		slots = append(slots, cardSlot{dmz: true})
	}

	numRows := (len(slots) + cols - 1) / cols
	rowHeights := make([]int, numRows)
	for r := range numRows {
		maxH := 180
		for c := range cols {
			idx := r*cols + c
			if idx >= len(slots) {
				break
			}
			h := measureSlotHeight(slots[idx].vlan, slots[idx].dmz)
			if h > maxH {
				maxH = h
			}
		}
		rowHeights[r] = maxH
	}

	totalH := vlanStartY + svgMargin
	for r, rh := range rowHeights {
		totalH += rh
		if r < numRows-1 {
			totalH += svgRowGap
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="UniFi Network Topology">`+"\n",
		canvasW, totalH, canvasW, totalH)

	b.WriteString(`  <defs>
    <marker id="arr-slate" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 1 1.5 L 8.5 5 L 1 8.5 z" fill="#475569"/>
    </marker>
    <marker id="arr-teal" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 1 1.5 L 8.5 5 L 1 8.5 z" fill="#0D9488"/>
    </marker>
    <style>
      .f { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      .h1 { font-size: 19px; font-weight: 700; fill: #0F172A; }
      .sub { font-size: 11.5px; fill: #475569; }
      .zh { font-size: 10.5px; font-weight: 700; letter-spacing: 0.6px; }
      .ct { font-size: 13.5px; font-weight: 700; fill: #0F172A; }
      .cs { font-size: 10.5px; fill: #475569; }
      .sec { font-size: 10px; font-weight: 700; letter-spacing: 0.4px; }
      .dn { font-size: 11.5px; font-weight: 600; fill: #0F172A; }
      .dm { font-size: 10px; fill: #475569; }
      .da { font-size: 10px; font-weight: 600; fill: #B45309; }
      .dt { font-size: 10px; font-weight: 600; fill: #0F766E; }
      .pill { font-size: 9px; font-weight: 700; }
    </style>
  </defs>
`)
	fmt.Fprintf(&b, `  <rect x="0" y="0" width="%d" height="%d" fill="#F8FAFC"/>`+"\n", canvasW, totalH)

	// Header + Legend
	fmt.Fprintf(&b, `  <text x="%d" y="32" class="f h1">UniFi Network Topology — Site %s</text>`+"\n", svgMargin, esc(m.Site))
	fmt.Fprintf(&b, `  <text x="%d" y="51" class="f sub">%d VLANs · %d Active Clients · %d UniFi Devices · %d Firewall Zones (%s)</text>`+"\n",
		svgMargin, len(m.VLANs), m.ClientCount, m.DeviceCount, len(m.Zones), esc(m.ControllerType))

	legX := canvasW - svgMargin - 395
	fmt.Fprintf(&b, `  <g transform="translate(%d, 22)">`+"\n", legX)
	b.WriteString(`    <rect x="0" y="0" width="10" height="10" rx="2" fill="#10B981"/><text x="15" y="9" class="f cs">OK placement</text>
    <rect x="108" y="0" width="10" height="10" rx="2" fill="#F59E0B"/><text x="123" y="9" class="f cs">Review</text>
    <rect x="180" y="0" width="10" height="10" rx="2" fill="#0D9488"/><text x="195" y="9" class="f cs">Candidate for Isolation</text>
    <rect x="330" y="0" width="10" height="10" rx="2" fill="#7C3AED"/><text x="345" y="9" class="f cs">DMZ</text>
  </g>
`)

	// Row 1: 3 Top Cards (WAN | Gateway | UniFi Switching & Wi-Fi)
	usableW := canvasW - svgMargin*2
	wanW := int(float64(usableW) * 0.27)
	gwW := int(float64(usableW) * 0.34)
	arrowGap := 46
	infraW := usableW - wanW - gwW - arrowGap*2

	wanX := svgMargin
	gwX := wanX + wanW + arrowGap
	infraX := gwX + gwW + arrowGap

	renderWANCard(&b, wanX, topY, wanW, topCardH, m.WANRoutes)
	renderGatewayCard(&b, gwX, topY, gwW, topCardH, m)
	renderInfraCard(&b, infraX, topY, infraW, topCardH, m.Infra)

	// Connectors between top cards
	midY := topY + topCardH/2
	fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#475569" stroke-width="1.8" marker-end="url(#arr-slate)"/>`+"\n",
		wanX+wanW, midY, gwX-4, midY)
	fmt.Fprintf(&b, `  <text x="%d" y="%d" text-anchor="middle" class="f pill" fill="#475569">WAN</text>`+"\n",
		wanX+wanW+arrowGap/2, midY-7)

	fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#475569" stroke-width="1.8" marker-end="url(#arr-slate)"/>`+"\n",
		gwX+gwW, midY, infraX-4, midY)
	fmt.Fprintf(&b, `  <text x="%d" y="%d" text-anchor="middle" class="f pill" fill="#475569">L2/PoE</text>`+"\n",
		gwX+gwW+arrowGap/2, midY-7)

	// Trunk bus from Gateway down to first VLAN row
	busY := topY + topCardH + 22
	gwMidX := gwX + gwW/2
	fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#2563EB" stroke-width="1.8"/>`+"\n",
		gwMidX, topY+topCardH, gwMidX, busY)
	firstRowCols := len(slots)
	if firstRowCols > cols {
		firstRowCols = cols
	}
	if firstRowCols > 0 {
		leftCenter := svgMargin + colW/2
		rightCenter := svgMargin + (firstRowCols-1)*(colW+svgColGap) + colW/2
		if firstRowCols > 1 {
			fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#94A3B8" stroke-width="1.6"/>`+"\n",
				leftCenter, busY, rightCenter, busY)
		}
		for c := range firstRowCols {
			cx := svgMargin + c*(colW+svgColGap) + colW/2
			stroke := "#2563EB"
			marker := "arr-slate"
			if slots[c].dmz || (slots[c].vlan != nil && slots[c].vlan.Isolated) {
				stroke = "#0D9488"
				marker = "arr-teal"
			}
			fmt.Fprintf(&b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.6" marker-end="url(#%s)"/>`+"\n",
				cx, busY, cx, vlanStartY-4, stroke, marker)
		}
	}

	// Render VLAN rows
	curY := vlanStartY
	for r := range numRows {
		rh := rowHeights[r]
		for c := range cols {
			idx := r*cols + c
			if idx >= len(slots) {
				break
			}
			cx := svgMargin + c*(colW+svgColGap)
			if slots[idx].dmz {
				renderUnusedDMZCard(&b, cx, curY, colW, rh)
			} else {
				renderVLANCard(&b, cx, curY, colW, rh, *slots[idx].vlan)
			}
		}
		curY += rh + svgRowGap
	}

	b.WriteString("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func renderWANCard(b *strings.Builder, x, y, w, h int, routes []WANRoute) {
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FFFFFF" stroke="#CBD5E1" stroke-width="1.5"/>`+"\n", x, y, w, h)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="26" rx="10" fill="#1E293B"/>`+"\n", x, y, w)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="12" fill="#1E293B"/>`+"\n", x, y+14, w)
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f zh" fill="#F8FAFC">INTERNET / WAN  (EXTERNAL)</text>`+"\n", x+12, y+17)

	cy := y + 46
	if len(routes) == 0 {
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dm">No active inbound WAN rules.</text>`+"\n", x+12, cy)
		return
	}
	maxChars := (w - 28) / 6
	for _, r := range routes {
		cls := "f dm"
		if r.Review {
			cls = "f da"
		}
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="%s">· %s</text>`+"\n", x+12, cy, cls, esc(truncate(r.Label, maxChars)))
		cy += 19
	}
}

func renderGatewayCard(b *strings.Builder, x, y, w, h int, m *Model) {
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FFFFFF" stroke="#2563EB" stroke-width="1.8"/>`+"\n", x, y, w, h)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="26" rx="10" fill="#1D4ED8"/>`+"\n", x, y, w)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="12" fill="#1D4ED8"/>`+"\n", x, y+14, w)

	title := "UNIFI GATEWAY / ROUTER"
	if m.Gateway != nil {
		title = strings.ToUpper(fmt.Sprintf("%s  (%s · v%s)", m.Gateway.Name, m.Gateway.Model, m.Gateway.Version))
	}
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f zh" fill="#FFFFFF">%s</text>`+"\n", x+12, y+17, esc(truncate(title, (w-24)/6)))

	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dn">Firewall Zones &amp; Inter-VLAN Segmentation</text>`+"\n", x+12, y+46)

	// Render zone pills neatly inside the gateway box.
	px := x + 12
	py := y + 58
	for _, z := range m.Zones {
		label := fmt.Sprintf("%s (%d)", z.Name, z.NetworkCount)
		pw := len(label)*6 + 18
		if px+pw > x+w-12 {
			px = x + 12
			py += 26
		}
		fill, stroke, txt := "#F1F5F9", "#CBD5E1", "#334155"
		switch strings.ToLower(z.Name) {
		case "internal":
			fill, stroke, txt = "#DBEAFE", "#93C5FD", "#1E40AF"
		case "hotspot":
			fill, stroke, txt = "#CCFBF1", "#5EEAD4", "#0F766E"
		case "dmz":
			fill, stroke, txt = "#F3E8FF", "#D8B4FE", "#6B21A8"
		default:
			if z.Isolated {
				fill, stroke, txt = "#CCFBF1", "#5EEAD4", "#0F766E"
			}
		}
		fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="21" rx="5" fill="%s" stroke="%s"/>`+"\n", px, py, pw, fill, stroke)
		fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="middle" class="f pill" fill="%s">%s</text>`+"\n", px+pw/2, py+14, txt, esc(label))
		px += pw + 7
	}
	if len(m.Zones) == 0 {
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dm">Classic controller (isolation inferred from network purpose &amp; flags).</text>`+"\n", x+12, py+14)
	}
}

func renderInfraCard(b *strings.Builder, x, y, w, h int, infra []InfraNode) {
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FFFFFF" stroke="#CBD5E1" stroke-width="1.5"/>`+"\n", x, y, w, h)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="26" rx="10" fill="#334155"/>`+"\n", x, y, w)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="12" fill="#334155"/>`+"\n", x, y+14, w)
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f zh" fill="#F8FAFC">UNIFI SWITCHING &amp; WI-FI (%d DEVICES)</text>`+"\n", x+12, y+17, len(infra))

	cy := y + 46
	if len(infra) == 0 {
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dm">No managed switches or APs adopted.</text>`+"\n", x+12, cy)
		return
	}
	for _, d := range infra {
		label := fmt.Sprintf("%s (%s)", d.Name, d.Model)
		maxLabel := (w - 220) / 6
		if maxLabel < 18 {
			maxLabel = 18
		}
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dn">%s</text>`+"\n", x+12, cy, esc(truncate(label, maxLabel)))
		right := d.IP
		if d.Uplink != "" {
			right = d.IP + " · " + d.Uplink
		}
		fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="end" class="mono dm">%s</text>`+"\n", x+w-12, cy, esc(truncate(right, 30)))
		cy += 19
	}
}

func renderVLANCard(b *strings.Builder, x, y, w, h int, vg VLANGroup) {
	border, headFill, headLine, badgeFill, badgeTxt := "#93C5FD", "#EFF6FF", "#BFDBFE", "#DBEAFE", "#1E40AF"
	if vg.Isolated {
		border, headFill, headLine, badgeFill, badgeTxt = "#5EEAD4", "#F0FDFA", "#99F6E4", "#CCFBF1", "#0F766E"
	}

	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FFFFFF" stroke="%s" stroke-width="1.5"/>`+"\n", x, y, w, h, border)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="%s"/>`+"\n", x, y, w, svgCardHead, headFill)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="14" fill="%s"/>`+"\n", x, y+svgCardHead-14, w, headFill)
	fmt.Fprintf(b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1"/>`+"\n", x, y+svgCardHead, x+w, y+svgCardHead, headLine)

	title := vg.Name
	if vg.VLAN != "" {
		title = fmt.Sprintf("%s (VLAN %s)", vg.Name, vg.VLAN)
	}
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f ct">%s</text>`+"\n", x+12, y+20, esc(truncate(title, (w-105)/7)))

	// Zone pill top-right
	zLabel := strings.ToUpper(vg.ZoneName)
	zw := len(zLabel)*6 + 14
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="18" rx="4" fill="%s"/>`+"\n", x+w-zw-10, y+8, zw, badgeFill)
	fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="middle" class="f pill" fill="%s">%s</text>`+"\n", x+w-zw/2-10, y+20, badgeTxt, esc(zLabel))

	sub := fmt.Sprintf("%s · %d client(s)", vg.Subnet, len(vg.Clients))
	if vg.Subnet == "" {
		sub = fmt.Sprintf("%d client(s)", len(vg.Clients))
	}
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="mono cs">%s</text>`+"\n", x+12, y+38, esc(sub))

	cy := y + svgCardHead + svgCardPad
	if len(vg.Clients) == 0 {
		fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="54" rx="7" fill="#FFFBEB" stroke="#F59E0B" stroke-dasharray="5 3"/>`+"\n", x+12, cy, w-24)
		fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="middle" class="f da">NO ACTIVE CLIENTS</text>`+"\n", x+w/2, cy+24)
		status := "Available network"
		if vg.Isolated {
			status = "Isolated VLAN ready for untrusted devices"
		}
		fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="middle" class="f dm">%s</text>`+"\n", x+w/2, cy+41, esc(status))
		return
	}

	// Render clients grouped cleanly by placement bucket (OK, Review, Candidate for Isolation).
	groups := []struct {
		p      Placement
		label  string
		fill   string
		stroke string
		txt    string
	}{
		{PlacementOK, "PLACEMENT OK", "#ECFDF5", "#A7F3D0", "#065F46"},
		{PlacementReview, "REVIEW PLACEMENT", "#FFFBEB", "#FCD34D", "#92400E"},
		{PlacementIsolate, "CANDIDATE FOR ISOLATED VLAN", "#F0FDFA", "#5EEAD4", "#0F766E"},
	}

	for _, grp := range groups {
		var items []ClientNode
		for _, cl := range vg.Clients {
			if cl.Placement == grp.p {
				items = append(items, cl)
			}
		}
		if len(items) == 0 {
			continue
		}
		gh := svgSecHead + len(items)*svgRowH + 8
		fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="7" fill="%s" stroke="%s" stroke-width="1"/>`+"\n",
			x+10, cy, w-20, gh, grp.fill, grp.stroke)
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f sec" fill="%s">%s (%d)</text>`+"\n",
			x+18, cy+16, grp.txt, grp.label, len(items))

		iy := cy + svgSecHead + 13
		maxNameChars := (w - 160) / 6
		if maxNameChars < 14 {
			maxNameChars = 14
		}
		for i, cl := range items {
			if i > 0 {
				fmt.Fprintf(b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-opacity="0.6" stroke-width="1"/>`+"\n",
					x+18, iy-13, x+w-18, iy-13, grp.stroke)
			}
			// Category pill + Client Name + Right-aligned IP
			tag, tagBg, tagFg := categoryBadge(cl.Class.Category)
			tagW := len(tag)*6 + 10
			fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="15" rx="3" fill="%s"/>`+"\n", x+18, iy-11, tagW, tagBg)
			fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="middle" class="f pill" fill="%s">%s</text>`+"\n", x+18+tagW/2, iy, tagFg, tag)

			fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dn">%s</text>`+"\n", x+23+tagW, iy, esc(truncate(cl.Name, maxNameChars)))
			fmt.Fprintf(b, `  <text x="%d" y="%d" text-anchor="end" class="mono dm">%s</text>`+"\n", x+w-18, iy, esc(cl.IP))

			// Second line: Role / Vendor / Link (or placement reason)
			meta := cl.Class.Role
			if cl.Class.Vendor != "" && !strings.Contains(strings.ToLower(meta), strings.ToLower(cl.Class.Vendor)) {
				meta = meta + " · " + cl.Class.Vendor
			}
			if cl.Link != "" {
				meta = meta + " · " + cl.Link
			}
			fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dm">%s</text>`+"\n", x+18, iy+15, esc(truncate(meta, (w-38)/5)))
			iy += svgRowH
		}
		cy += gh + 10
	}
}

func renderUnusedDMZCard(b *strings.Builder, x, y, w, h int) {
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FFFFFF" stroke="#C4B5FD" stroke-width="1.5" stroke-dasharray="6 4"/>`+"\n", x, y, w, h)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="#FAF5FF"/>`+"\n", x, y, w, svgCardHead)
	fmt.Fprintf(b, `  <rect x="%d" y="%d" width="%d" height="14" fill="#FAF5FF"/>`+"\n", x, y+svgCardHead-14, w)
	fmt.Fprintf(b, `  <line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#E9D5FF" stroke-width="1"/>`+"\n", x, y+svgCardHead, x+w, y+svgCardHead)
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f ct" fill="#581C87">DMZ Zone (Unused)</text>`+"\n", x+12, y+20)
	fmt.Fprintf(b, `  <text x="%d" y="%d" class="f cs">0 VLANs assigned</text>`+"\n", x+12, y+38)

	cy := y + svgCardHead + 28
	lines := []string{
		"WAN-exposed web entrypoint",
		"detected in Internal zone.",
		"",
		"Assigning a DMZ VLAN isolates",
		"public-facing reverse proxies",
		"from initiating traffic into",
		"Internal LAN hosts.",
	}
	for _, l := range lines {
		fmt.Fprintf(b, `  <text x="%d" y="%d" class="f dm">%s</text>`+"\n", x+14, cy, esc(l))
		cy += 17
	}
}

func measureSlotHeight(vg *VLANGroup, dmz bool) int {
	if dmz {
		return svgCardHead + 170
	}
	if vg == nil || len(vg.Clients) == 0 {
		return svgCardHead + svgCardPad + 70
	}
	h := svgCardHead + svgCardPad
	counts := map[Placement]int{}
	for _, cl := range vg.Clients {
		counts[cl.Placement]++
	}
	for _, p := range []Placement{PlacementOK, PlacementReview, PlacementIsolate} {
		if n := counts[p]; n > 0 {
			h += svgSecHead + n*svgRowH + 18
		}
	}
	return h + 6
}

func categoryBadge(cat classify.Category) (label, bg, fg string) {
	switch cat {
	case classify.CategoryServer:
		return "SRV", "#DBEAFE", "#1E40AF"
	case classify.CategoryVM:
		return "VM", "#E0E7FF", "#3730A3"
	case classify.CategoryBMC:
		return "BMC", "#FEE2E2", "#991B1B"
	case classify.CategoryNetService:
		return "NET", "#F3E8FF", "#6B21A8"
	case classify.CategoryCamera:
		return "CAM", "#FEF3C7", "#92400E"
	case classify.CategoryPrinter:
		return "PRT", "#E2E8F0", "#334155"
	case classify.CategoryMedia:
		return "AV", "#FCE7F3", "#9D174D"
	case classify.CategoryIoT:
		return "IOT", "#CCFBF1", "#0F766E"
	case classify.CategoryPersonal:
		return "DEV", "#D1FAE5", "#065F46"
	default:
		return "?", "#F1F5F9", "#475569"
	}
}

func esc(s string) string {
	return html.EscapeString(s)
}

func truncate(s string, max int) string {
	if max <= 3 || len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}
