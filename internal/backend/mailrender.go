package backend

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/goodnightsec/gn-check/internal/store"
)

// The notification mail documents live as template files so the markup stays
// reviewable in isolation and html/template escapes every dynamic value
// contextually (hrefs included). They are embedded at build time — templates
// ship in the binary, nothing is loaded at runtime.
//
//go:embed mailtemplates/*.html
var mailTemplateFS embed.FS

// The brand logo in the mail header is the Goodnight Check lockup, as in the
// app header: a PNG rendition (108 px high, shown at 36 px) of
// web/public/goodnight-check-lockup-on-dark.svg, because Gmail and Outlook
// don't render SVG. The mail header bar is midnight, so it is the -on-dark
// variant, with the midnight bar color (#020617) baked in as an opaque
// backing: Outlook classic in dark mode lightens the bar but never recolors
// an image, so a transparent lockup would lose its white "Goodnight". It rides along as an inline CID part (Content-ID
// <goodnight-check-lockup-on-dark.png>, set by go-mail from the file name), so
// the markup references src="cid:goodnight-check-lockup-on-dark.png" and the
// mail still loads nothing from the network.
//
//go:embed mailtemplates/goodnight-check-lockup-on-dark.png
var mailLogoPNG []byte

// mailLogoCID is the cid: reference the mail templates use for the logo.
const mailLogoCID = "cid:goodnight-check-lockup-on-dark.png"

// mailLogoInline is the inline logo attachment carried by both HTML mails.
func mailLogoInline() []MailImage {
	return []MailImage{{Name: strings.TrimPrefix(mailLogoCID, "cid:"), Data: mailLogoPNG}}
}

var mailTemplates = template.Must(template.New("mail").Funcs(template.FuncMap{
	"sevColor":    sevColor,
	"msoHead":     msoHead,
	"msoButton":   msoButton,
	"notMsoStart": notMsoStart,
	"notMsoEnd":   notMsoEnd,
}).ParseFS(mailTemplateFS, "mailtemplates/*.html"))

// Outlook classic for Windows renders mail with Word's engine. Markup only for
// it goes in conditional comments (<!--[if mso]>), but html/template drops
// every comment in template text, so these helpers emit them as trusted HTML.
// Their markup is constant except msoButton's href and label, which it
// escapes itself.

// msoHead lets Word show the PNG logo and lays the mail out at 96 dpi, so the
// VML button keeps its pixel size on scaled displays.
func msoHead() template.HTML {
	return `<!--[if mso]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->`
}

// msoButton is the "bulletproof" button for Word: a VML roundrect with a fixed
// size, fill and white text, which Word neither pads away nor recolors like
// the inline link. Other clients skip it and show the table-cell button that
// follows it between notMsoStart and notMsoEnd. The href must be an absolute
// http(s) URL, as html/template would require of an href; anything else
// renders as "#".
func msoButton(href, label string) template.HTML {
	if u, err := url.Parse(href); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		href = "#"
	}
	return template.HTML(`<!--[if mso]>` +
		`<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" xmlns:w="urn:schemas-microsoft-com:office:word" href="` + template.HTMLEscapeString(href) + `" style="height:33px;v-text-anchor:middle;width:104px;" arcsize="18%" stroke="f" fillcolor="#4f46e5">` +
		`<w:anchorlock/>` +
		`<center style="color:#ffffff;font-family:'Segoe UI',Arial,sans-serif;font-size:13px;font-weight:600;">` + template.HTMLEscapeString(label) + `</center>` +
		`</v:roundrect>` +
		`<![endif]-->`)
}

// notMsoStart and notMsoEnd enclose markup that every client but Word shows.
func notMsoStart() template.HTML { return `<!--[if !mso]><!-->` }
func notMsoEnd() template.HTML   { return `<!--<![endif]-->` }

// renderMailTemplate executes one embedded mail document.
func renderMailTemplate(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := mailTemplates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("render mail %s: %w", name, err)
	}
	return buf.String(), nil
}

// Mail styling mirrors the light theme of the web app (docs/UI_STYLE_GUIDE.md):
// the severity ramp red→orange→amber→yellow→sky for severities, the Badge tone
// scale (accent/warning/success) for statuses, indigo links and buttons. Hex
// values are inline because mail clients strip classes and <style> blocks.
//
// severityChipColors pair a [background, text] color per Nuclei severity, as
// web/src/components/ui.tsx SeverityBadge renders it.
var severityChipColors = map[string][2]string{
	"critical": {"#fee2e2", "#991b1b"},
	"high":     {"#ffedd5", "#9a3412"},
	"medium":   {"#fef3c7", "#92400e"},
	"low":      {"#fef9c3", "#854d0e"},
	"info":     {"#e0f2fe", "#075985"},
}

// statusChipColors pair a [background, text] color per digest status.
var statusChipColors = map[string][2]string{
	"new":     {"#e0e7ff", "#3730a3"},
	"changed": {"#fef3c7", "#92400e"},
	"fixed":   {"#dcfce7", "#166534"},
}

// neutralChip is the fallback chip for unknown or unexpected values.
var neutralChip = [2]string{"#f5f5f5", "#404040"}

// sevColors are the text colors of emphasized (non-zero) count cells on white.
var sevColors = map[string]string{
	"critical": "#b91c1c",
	"high":     "#c2410c",
	"medium":   "#b45309",
	"low":      "#a16207",
	"info":     "#0369a1",
}

// sevColor is a template function: the count text color for a severity bucket.
func sevColor(sev string) string {
	if c, ok := sevColors[strings.ToLower(sev)]; ok {
		return c
	}
	return "#737373"
}

func chipColor(m map[string][2]string, key string) (string, string) {
	if c, ok := m[strings.ToLower(key)]; ok {
		return c[0], c[1]
	}
	return neutralChip[0], neutralChip[1]
}

func statusText(status string) string {
	switch status {
	case "new", "changed", "fixed":
		return strings.ToUpper(status[:1]) + status[1:]
	case "":
		return "Unknown"
	}
	return status
}

var severityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

func severityCount(c store.SeverityCounts, sev string) int {
	switch sev {
	case "critical":
		return c.Critical
	case "high":
		return c.High
	case "medium":
		return c.Medium
	case "low":
		return c.Low
	case "info":
		return c.Info
	}
	return c.Unknown
}

func severityCells(c store.SeverityCounts) []digestCountCell {
	cells := make([]digestCountCell, 0, len(severityOrder))
	for _, sev := range severityOrder {
		cells = append(cells, digestCountCell{Severity: sev, N: severityCount(c, sev)})
	}
	return cells
}

// digestMailData is the context of mailtemplates/digest.html. The brand and
// footer partials in layout.html read ScanID and Policy from the same struct.
type digestMailData struct {
	Subject string
	Title   string
	Policy  string
	ScanURL string
	ScanID  string

	Counts []digestCountRow

	Findings   []digestFindingRow
	TotalCount int
	ExtraCount int
}

type digestCountRow struct {
	Status string
	Cells  []digestCountCell
	Total  int
}

type digestCountCell struct {
	Severity string
	N        int
}

// mailBadge is the context of the "badge" partial in layout.html.
type mailBadge struct {
	BG, FG, Text string
}

type digestFindingRow struct {
	StatusBG   string
	StatusFG   string
	StatusText string
	SevBG      string
	SevFG      string
	Severity   string
	LinkText   string
	TemplateID string
	MatchedAt  string
	URL        string
}

// StatusBadge is the row's status badge.
func (r digestFindingRow) StatusBadge() mailBadge {
	return mailBadge{BG: r.StatusBG, FG: r.StatusFG, Text: r.StatusText}
}

// SevBadge is the row's severity badge.
func (r digestFindingRow) SevBadge() mailBadge {
	return mailBadge{BG: r.SevBG, FG: r.SevFG, Text: r.Severity}
}

func newDigestMailData(scan store.ScanRow, base, title, subject string, p store.ScanDigestPayload, listed []store.ScanDigestFinding, extra int) digestMailData {
	data := digestMailData{
		Subject:    subject,
		Title:      title,
		Policy:     scan.ScanPolicyName,
		ScanURL:    joinURL(base, "/scans/"+scan.ID),
		ScanID:     scan.ID,
		TotalCount: p.New.Total() + p.Changed.Total() + p.Fixed.Total(),
		ExtraCount: extra,
	}
	data.Counts = []digestCountRow{
		{Status: "New", Cells: severityCells(p.New), Total: p.New.Total()},
		{Status: "Changed", Cells: severityCells(p.Changed), Total: p.Changed.Total()},
		{Status: "Fixed", Cells: severityCells(p.Fixed), Total: p.Fixed.Total()},
	}
	data.Findings = make([]digestFindingRow, 0, len(listed))
	for _, f := range listed {
		link := f.Name
		if link == "" {
			link = f.TemplateID
		}
		sevBG, sevFG := chipColor(severityChipColors, f.Severity)
		stBG, stFG := chipColor(statusChipColors, f.Status)
		displaySev := f.Severity
		if displaySev == "" {
			displaySev = "unknown"
		}
		data.Findings = append(data.Findings, digestFindingRow{
			StatusBG:   stBG,
			StatusFG:   stFG,
			StatusText: statusText(f.Status),
			SevBG:      sevBG,
			SevFG:      sevFG,
			Severity:   displaySev,
			LinkText:   link,
			TemplateID: f.TemplateID,
			MatchedAt:  f.MatchedAt,
			URL:        joinURL(base, fmt.Sprintf("/findings/%d", f.ID)),
		})
	}
	return data
}

// failedMailData is the context of mailtemplates/failed.html.
type failedMailData struct {
	Subject string
	Title   string
	Policy  string
	ScanURL string
	ScanID  string
	Reason  string
}

func newFailedMailData(scan store.ScanRow, base, title, subject, reason string) failedMailData {
	return failedMailData{
		Subject: subject,
		Title:   title,
		Policy:  scan.ScanPolicyName,
		ScanURL: joinURL(base, "/scans/"+scan.ID),
		ScanID:  scan.ID,
		Reason:  reason,
	}
}
