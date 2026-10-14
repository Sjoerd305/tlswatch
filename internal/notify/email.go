package notify

import (
	"bytes"
	"html/template"
	"strings"
)

// The HTML part of a mail follows the UI (design/README.md): the dark top
// bar with the wordmark, a white card, status colours only for status
// (pills and the countdown), uppercase labels and mono identifiers. Mail
// clients drop or ignore much of CSS, so the light tokens are inline styles
// and a <style> block adds the dark tokens for clients that honour it.
// Fonts fall back to system faces; a mail does not load web fonts.

const (
	sansStack = `'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif`
	monoStack = `'IBM Plex Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace`
)

// statusColors are the light status token pairs (ink, background) by
// subject tag.
var statusColors = map[string][2]string{
	"critical": {"#c62828", "#fde8e8"},
	"warning":  {"#a86400", "#fdf1dc"},
	"info":     {"#2f6fd1", "#e6eefb"},
	"resolved": {"#1f8a4c", "#e3f3ea"},
	"ok":       {"#1f8a4c", "#e3f3ea"},
	"off":      {"#6b7785", "#e9ecef"},
}

func statusColor(tag string) [2]string {
	if c, ok := statusColors[tag]; ok {
		return c
	}
	return statusColors["off"]
}

// emailStyles are the inline styles by name.
var emailStyles = map[string]string{
	"body":    "margin:0;padding:0;background:#f5f6f7;",
	"outer":   "padding:24px 12px;",
	"bar":     "background:#1c2430;color:#e8edf2;padding:12px 20px;border-radius:6px 0 0 0;font:600 15px/1.2 " + sansStack + ";",
	"mark":    "color:#6ea0ec;",
	"barnote": "background:#1c2430;color:#95a2b1;padding:12px 20px;border-radius:0 6px 0 0;font:400 12px/1.2 " + sansStack + ";text-align:right;",
	"card":    "background:#ffffff;border:1px solid #dde2e7;border-top:0;border-radius:0 0 6px 6px;padding:22px 24px 24px;font:400 13px/1.5 " + sansStack + ";color:#1a2330;",
	"event":   "font:400 12px/1.4 " + sansStack + ";color:#5c6b7a;",
	"title":   "margin:10px 0 0;font:600 20px/1.3 " + sansStack + ";color:#1a2330;",
	"muted":   "color:#5c6b7a;",
	"mono":    "font-family:" + monoStack + ";font-size:12px;",
	"k":       "padding:7px 12px 7px 0;width:110px;vertical-align:top;border-top:1px solid #eaeef1;font:600 11px/1.6 " + sansStack + ";letter-spacing:.04em;text-transform:uppercase;color:#5c6b7a;",
	"v":       "padding:7px 0;vertical-align:top;border-top:1px solid #eaeef1;color:#1a2330;word-break:break-word;",
	"cell":    "padding:7px 10px 7px 0;vertical-align:top;border-top:1px solid #eaeef1;color:#1a2330;",
	"num":     "padding:7px 10px 7px 0;vertical-align:top;border-top:1px solid #eaeef1;text-align:right;white-space:nowrap;font-family:" + monoStack + ";font-size:12px;",
	"section": "padding:22px 0 6px;font:600 12px/1.2 " + sansStack + ";letter-spacing:.04em;text-transform:uppercase;color:#5c6b7a;",
	"tile":    "padding:12px 14px;border:1px solid #dde2e7;border-radius:6px;background:#ffffff;",
	"tilek":   "font:600 11px/1.2 " + sansStack + ";letter-spacing:.04em;text-transform:uppercase;color:#5c6b7a;",
	"button":  "display:inline-block;background:#2f6fd1;color:#ffffff;text-decoration:none;font:600 13px/1 " + sansStack + ";padding:10px 16px;border-radius:6px;",
	"footer":  "padding:14px 4px 0;font:400 12px/1.5 " + sansStack + ";color:#5c6b7a;text-align:center;",
	"link":    "color:#2f6fd1;",
	"pre":     "display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;",
}

// darkCSS swaps in the dark tokens where the client supports it; classes
// mirror the inline style names.
const darkCSS = `
:root { color-scheme: light dark; supported-color-schemes: light dark; }
@media (prefers-color-scheme: dark) {
  .body, .outer { background:#0f141a !important; }
  .bar, .barnote { background:#0b0f14 !important; }
  .card { background:#171d25 !important; border-color:#2a3442 !important; color:#e6ebf0 !important; }
  .title, .v, .cell { color:#e6ebf0 !important; }
  .k, .v, .cell, .num { border-color:#222b36 !important; }
  .muted, .event, .k, .section, .tilek, .footer { color:#97a3b1 !important; }
  .tile { background:#171d25 !important; border-color:#2a3442 !important; }
  .button { background:#6ea0ec !important; color:#0f141a !important; }
  .link { color:#6ea0ec !important; }
  .s-critical { color:#f06565 !important; } .b-critical { background:#3a1b1b !important; }
  .s-warning { color:#f0b84d !important; } .b-warning { background:#332a12 !important; }
  .s-info { color:#6ea0ec !important; } .b-info { background:#17273d !important; }
  .s-resolved, .s-ok { color:#4cc27a !important; } .b-resolved, .b-ok { background:#15301f !important; }
  .s-off { color:#8e9aa8 !important; } .b-off { background:#262e38 !important; }
}`

var emailFuncs = template.FuncMap{
	// st returns the named inline style.
	"st": func(name string) template.CSS { return template.CSS(emailStyles[name]) }, // #nosec G203 -- constant styles from this file
	// pill styles a status pill for a subject tag.
	"pill": func(tag string) template.CSS {
		c := statusColor(tag)
		// #nosec G203 -- built from constants: the palette, not the tag itself
		return template.CSS("display:inline-block;padding:2px 7px;border-radius:3px;font:600 11px/1.3 " + sansStack +
			";letter-spacing:.04em;text-transform:uppercase;color:" + c[0] + ";background:" + c[1] + ";")
	},
	// ink colours a status figure (the countdown, a days-left number).
	"ink": func(tag string) template.CSS { return template.CSS("color:" + statusColor(tag)[0] + ";") }, // #nosec G203 -- palette constant
	"short": func(tag string) string {
		switch tag {
		case "critical":
			return "crit"
		case "warning":
			return "warn"
		}
		return tag
	},
}

var emailTemplates = template.Must(template.New("email").Funcs(emailFuncs).Parse(`
{{define "layout"}}<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">
<title>{{.Title}}</title>
<style>{{.CSS}}</style>
</head>
<body class="body" style="{{st "body"}}">
<div style="{{st "pre"}}">{{.Preheader}}</div>
<table role="presentation" class="outer" width="100%" cellpadding="0" cellspacing="0" border="0" style="{{st "body"}}"><tr><td align="center" class="outer" style="{{st "outer"}}">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;">
<tr>
<td class="bar" style="{{st "bar"}}"><span class="mark" style="{{st "mark"}}">&#9632;</span>&nbsp;tlswatch</td>
<td class="barnote" style="{{st "barnote"}}">{{.Label}}</td>
</tr>
<tr><td colspan="2" class="card" style="{{st "card"}}">
{{- if eq .Kind "alert"}}{{template "alert" .Alert}}{{end}}
{{- if eq .Kind "batch"}}{{template "batch" .Batch}}{{end}}
{{- if eq .Kind "digest"}}{{template "digest" .Digest}}{{end}}
{{- if eq .Kind "test"}}{{template "test" .Test}}{{end}}
{{- if .Link}}
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin-top:20px;"><tr><td><a class="button" href="{{.Link}}" style="{{st "button"}}">{{.LinkText}}</a></td></tr></table>
{{- end}}
</td></tr>
<tr><td colspan="2" class="footer" style="{{st "footer"}}">Sent by tlswatch</td></tr>
</table>
</td></tr></table>
</body></html>{{end}}

{{define "alert"}}
<div class="event" style="{{st "event"}}"><span class="s-{{.Tag}} b-{{.Tag}}" style="{{pill .Tag}}">{{short .Tag}}</span>&nbsp; {{.Event}}</div>
<h1 class="title" style="{{st "title"}}">{{.Title}}</h1>
{{- if .Countdown}}
<div style="margin-top:14px;"><span class="s-{{.Tag}}" style="font:600 28px/1 {{st "sans"}}{{ink .Tag}}">{{.Countdown}}</span> <span class="muted" style="{{st "muted"}}">{{.CountdownNote}}</span></div>
{{- end}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:16px;border-collapse:collapse;">
{{- range .Rows}}
<tr><td class="k" style="{{st "k"}}">{{.K}}</td><td class="v" style="{{st "v"}}{{if .Mono}}{{st "mono"}}{{end}}">{{.V}}</td></tr>
{{- end}}
</table>
{{end}}

{{define "batch"}}
<h1 class="title" style="{{st "title"}}margin-top:0;">{{.Title}}</h1>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:16px;border-collapse:collapse;">
{{- range .Rows}}
<tr><td class="cell" style="{{st "cell"}}width:1%;white-space:nowrap;"><span class="s-{{.Tag}} b-{{.Tag}}" style="{{pill .Tag}}">{{short .Tag}}</span></td><td class="cell" style="{{st "cell"}}">{{.Text}}</td></tr>
{{- end}}
{{- if .More}}
<tr><td class="cell" style="{{st "cell"}}"></td><td class="cell muted" style="{{st "cell"}}{{st "muted"}}">and {{.More}} more</td></tr>
{{- end}}
</table>
{{end}}

{{define "digest"}}
<div class="event" style="{{st "event"}}">{{.Date}}</div>
<h1 class="title" style="{{st "title"}}">{{if .Calm}}Nothing needs attention{{else}}Weekly digest{{end}}</h1>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:16px;"><tr>
{{- range $i, $t := .Tiles}}
<td width="33%" style="{{if $i}}padding-left:8px;{{end}}vertical-align:top;"><div class="tile" style="{{st "tile"}}"><div class="tilek" style="{{st "tilek"}}">{{$t.K}}</div><div class="s-{{$t.Tag}}" style="font:600 28px/1.2 {{st "sans"}}{{ink $t.Tag}}">{{$t.N}}</div></div></td>
{{- end}}
</tr></table>
<div class="section" style="{{st "section"}}">Open findings</div>
{{- if .Findings}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
{{- range .Findings}}
<tr><td class="cell" style="{{st "cell"}}width:1%;white-space:nowrap;"><span class="s-{{.Severity}} b-{{.Severity}}" style="{{pill .Severity}}">{{short .Severity}}</span></td>
<td class="cell" style="{{st "cell"}}"><span style="{{st "mono"}}">{{.HostPort}}</span> {{.Kind}}<br><span class="muted" style="{{st "muted"}}">{{.Details}}{{if .AckBy}} · acknowledged by {{.AckBy}}{{end}}</span></td></tr>
{{- end}}
</table>
{{- else}}<div class="muted" style="{{st "muted"}}">None.</div>{{end}}
<div class="section" style="{{st "section"}}">Expiring in the next 30 days</div>
{{- if .Expiring}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
{{- range .Expiring}}
<tr><td class="cell" style="{{st "cell"}}{{st "mono"}}width:1%;white-space:nowrap;">{{.Date}}</td><td class="num s-{{.Tag}}" style="{{st "num"}}width:1%;{{ink .Tag}}">{{.Days}} d</td><td class="cell" style="{{st "cell"}}">{{.Name}} <span class="muted" style="{{st "muted"}}{{st "mono"}}">{{.HostPort}}</span></td></tr>
{{- end}}
</table>
{{- else}}<div class="muted" style="{{st "muted"}}">None.</div>{{end}}
<div class="section" style="{{st "section"}}">Failed their last check</div>
{{- if .Failed}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
{{- range .Failed}}
<tr><td class="cell" style="{{st "cell"}}">{{.Name}} <span class="muted" style="{{st "muted"}}{{st "mono"}}">{{.HostPort}}</span><br><span class="s-critical" style="{{ink "critical"}}">{{.Error}}</span></td></tr>
{{- end}}
</table>
{{- else}}<div class="muted" style="{{st "muted"}}">None.</div>{{end}}
{{end}}

{{define "test"}}
<div class="event" style="{{st "event"}}"><span class="s-ok b-ok" style="{{pill "ok"}}">test</span>&nbsp; Channel {{.Channel}}</div>
<h1 class="title" style="{{st "title"}}">Test message</h1>
<p style="margin:12px 0 0;">If you can read this, alerts sent through the channel <strong>{{.Channel}}</strong> arrive here, in this style.</p>
{{end}}
`))

func init() { emailStyles["sans"] = sansStack + ";" }

// emailDoc is one HTML mail.
type emailDoc struct {
	Kind      string // alert, batch, digest, test
	Title     string
	Preheader string
	Label     string // right side of the top bar
	Link      string
	LinkText  string
	CSS       template.CSS
	Alert     *alertView
	Batch     *batchView
	Digest    *digestView
	Test      *testView
}

type kv struct {
	K, V string
	Mono bool
}

type alertView struct {
	Tag, Event, Title        string
	Countdown, CountdownNote string
	Rows                     []kv
}

type batchRow struct{ Tag, Text string }

type batchView struct {
	Title string
	Count int
	Rows  []batchRow
	More  int
}

type tile struct {
	K, Tag string
	N      int
}

type digestView struct {
	DigestData
	Calm  bool
	Tiles []tile
}

type testView struct{ Channel string }

// renderHTML renders an email; an error leaves the mail plain text.
func renderHTML(d emailDoc) string {
	d.CSS = template.CSS(darkCSS) // #nosec G203 -- constant
	if d.LinkText == "" {
		d.LinkText = "Open in tlswatch"
	}
	var b bytes.Buffer
	if err := emailTemplates.ExecuteTemplate(&b, "layout", d); err != nil {
		return ""
	}
	return b.String()
}

// untagged returns a subject without its leading [tag].
func untagged(subject string) string {
	if strings.HasPrefix(subject, "[") {
		if i := strings.Index(subject, "] "); i > 0 {
			return subject[i+2:]
		}
	}
	return subject
}

// subjectTag returns the tag of a subject, "info" when it has none.
func subjectTag(subject string) string { return subjectTags[tagRank(subject)] }
