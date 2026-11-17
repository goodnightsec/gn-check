package backend

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
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

// The mail header bar and the "Open scan" button are images, because Outlook
// classic in dark mode recolors both a cell background and a VML shape but
// never an image. The bar is one 600x72 picture (stored at 3x, 1800x216) with
// the Goodnight Check lockup, as in the app header, composited on the midnight
// color #020617; the button is a 104x33 picture (3x) with the indigo fill and
// the white label baked in. Both are PNG renditions, because Gmail and Outlook
// don't render SVG, and ride along as inline CID parts (Content-ID set by
// go-mail from the file name), so the mail loads nothing from the network.
// The cells around them keep bgcolor and the alt text, for clients that block
// images.
//
//go:embed mailtemplates/goodnight-check-brand-bar.png
var mailBrandBarPNG []byte

//go:embed mailtemplates/open-scan-button.png
var mailButtonPNG []byte

// The cid: references the mail templates use for the two images.
const (
	mailBrandBarName = "goodnight-check-brand-bar.png"
	mailButtonName   = "open-scan-button.png"
	mailBrandBarCID  = "cid:" + mailBrandBarName
	mailButtonCID    = "cid:" + mailButtonName
)

// mailInlineImages are the inline image attachments carried by both HTML mails.
func mailInlineImages() []MailImage {
	return []MailImage{
		{Name: mailBrandBarName, Data: mailBrandBarPNG},
		{Name: mailButtonName, Data: mailButtonPNG},
	}
}

var mailTemplates = template.Must(template.New("mail").Funcs(template.FuncMap{
	"sevColor": sevColor,
	"msoHead":  msoHead,
}).ParseFS(mailTemplateFS, "mailtemplates/*.html"))

// Outlook classic for Windows renders mail with Word's engine. Markup only for
// it goes in a conditional comment (<!--[if mso]>), but html/template drops
// every comment in template text, so msoHead emits it as constant trusted HTML.

// msoHead lets Word show the PNG images and lays the mail out at 96 dpi, so the
// images keep their pixel size on scaled displays.
func msoHead() template.HTML {
	return `<!--[if mso]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->`
}

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
