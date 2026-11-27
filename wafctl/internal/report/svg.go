package report

import (
	"fmt"
	"html"
	"html/template"
	"strings"
)

// Bar is one labelled value.
type Bar struct {
	Label string
	Value float64
}

// HBars renders horizontal bars scaled to the max value (all-zero input draws empty bars).
func HBars(bars []Bar, color string) template.HTML {
	const w, rowH, labelW, barW = 760, 22, 330, 340
	max := 0.0
	for _, b := range bars {
		if b.Value > max {
			max = b.Value
		}
	}
	var s strings.Builder
	h := rowH*len(bars) + 4
	fmt.Fprintf(&s, `<svg class="chart" width="%d" height="%d" viewBox="0 0 %d %d" role="img">`, w, h, w, h)
	for i, b := range bars {
		y := i*rowH + 2
		bw := 0.0
		if max > 0 {
			bw = b.Value / max * barW
		}
		fmt.Fprintf(&s, `<text x="%d" y="%d" text-anchor="end" class="lbl">%s</text>`, labelW-6, y+15, html.EscapeString(trunc(b.Label, 48)))
		fmt.Fprintf(&s, `<rect x="%d" y="%d" width="%.1f" height="%d" fill="%s"/>`, labelW, y+3, bw, rowH-6, color)
		fmt.Fprintf(&s, `<text x="%.1f" y="%d" class="val">%s</text>`, float64(labelW)+bw+6, y+15, num(b.Value))
	}
	s.WriteString(`</svg>`)
	return template.HTML(s.String())
}

// Stack is one time bucket of the timeline.
type Stack struct {
	Label              string
	Allow, Block, Fail float64
}

// Columns renders stacked allow/block/fail columns per bucket.
func Columns(st []Stack) template.HTML {
	const h, plotH, top, left = 220, 170, 10, 50
	colW := 24
	if len(st) > 30 {
		colW = 12
	}
	if len(st) > 60 {
		colW = 6
	}
	w := left + len(st)*(colW+2) + 10
	if w < 300 {
		w = 300
	}
	max := 0.0
	for _, c := range st {
		if t := c.Allow + c.Block + c.Fail; t > max {
			max = t
		}
	}
	var s strings.Builder
	fmt.Fprintf(&s, `<svg class="chart" width="%d" height="%d" viewBox="0 0 %d %d" role="img">`, w, h, w, h)
	fmt.Fprintf(&s, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#999"/>`, left, top+plotH, w-5, top+plotH)
	fmt.Fprintf(&s, `<text x="%d" y="%d" text-anchor="end" class="val">%s</text>`, left-4, top+8, num(max))
	fmt.Fprintf(&s, `<text x="%d" y="%d" text-anchor="end" class="val">0</text>`, left-4, top+plotH)
	lastLbl := -1000
	for i, c := range st {
		x := left + 2 + i*(colW+2)
		y := float64(top + plotH)
		for _, part := range []struct {
			v   float64
			col string
		}{{c.Allow, "#4c9a2a"}, {c.Block, "#c0392b"}, {c.Fail, "#8e44ad"}} {
			ph := 0.0
			if max > 0 {
				ph = part.v / max * plotH
			}
			y -= ph
			fmt.Fprintf(&s, `<rect x="%d" y="%.1f" width="%d" height="%.1f" fill="%s"><title>%s</title></rect>`, x, y, colW, ph, part.col,
				html.EscapeString(fmt.Sprintf("%s allow %s block %s fail %s", c.Label, num(c.Allow), num(c.Block), num(c.Fail))))
		}
		if (i == 0 || i == len(st)-1 || (len(st) > 8 && i%(len(st)/6+1) == 0)) && x-lastLbl >= 48 {
			lastLbl = x
			fmt.Fprintf(&s, `<text x="%d" y="%d" class="val">%s</text>`, x, h-22, html.EscapeString(shortHour(c.Label)))
		}
	}
	fmt.Fprintf(&s, `<rect x="%d" y="%d" width="10" height="10" fill="#4c9a2a"/><text x="%d" y="%d" class="val">ALLOW</text>`, left, h-12, left+14, h-3)
	fmt.Fprintf(&s, `<rect x="%d" y="%d" width="10" height="10" fill="#c0392b"/><text x="%d" y="%d" class="val">BLOCK</text>`, left+70, h-12, left+84, h-3)
	fmt.Fprintf(&s, `<rect x="%d" y="%d" width="10" height="10" fill="#8e44ad"/><text x="%d" y="%d" class="val">FAIL</text>`, left+140, h-12, left+154, h-3)
	s.WriteString(`</svg>`)
	return template.HTML(s.String())
}

func shortHour(s string) string { // "2026-11-27 10:00:00" -> "27 10h"
	if len(s) >= 13 {
		return s[8:10] + " " + s[11:13] + "h"
	}
	return s
}

func num(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.2f", v)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
