package passwordlinks

import (
	htmltemplate "html/template"
	"strings"
	texttemplate "text/template"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/elcanotek/auth/internal/store"
)

// message is one rendered email.
type message struct {
	Subject, Text, HTML string
}

// messageData is what the templates read. Every value is escaped by the HTML
// template; the text template writes them as they are (plain text).
type messageData struct {
	Brand     string
	Link      string
	SignInURL string
	Expires   string
	Reset     bool
}

const textBody = `{{if .Reset}}An administrator reset the password for your {{.Brand}} account. Your old password no longer works.

Choose a new password here (the link works once):{{else}}You have an account for {{.Brand}}.

Choose your password here (the link works once):{{end}}
{{.Link}}

The link expires {{.Expires}}. Then sign in at {{.SignInURL}}

{{if .Reset}}If you did not expect this email, tell your administrator.{{else}}If you were not expecting this email, you can ignore it: nothing happens unless the link is used.{{end}}
`

// The HTML is a single column with inline styles (mail clients drop style
// sheets) and no images or other remote content. Every link carries
// ses:no-track, so SES click tracking (a configuration set may turn it on)
// never rewrites it through a tracker; the SendGrid driver turns tracking
// off itself.
const htmlBody = `<!doctype html>
<html lang="en">
<body style="margin:0;padding:24px;background:#f4f5f9;font:16px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1a1a1a">
<div style="max-width:32rem;margin:0 auto;padding:32px;background:#ffffff;border-radius:12px;border:1px solid #e1e4ee">
<p style="margin:0 0 16px;font-size:12px;letter-spacing:.14em;text-transform:uppercase;font-weight:700;color:#5b6070">{{.Brand}}</p>
{{if .Reset}}<h1 style="margin:0 0 12px;font-size:22px">Choose a new password</h1>
<p style="margin:0 0 20px">An administrator reset the password for your {{.Brand}} account. Your old password no longer works.</p>
{{else}}<h1 style="margin:0 0 12px;font-size:22px">Choose your password</h1>
<p style="margin:0 0 20px">You have an account for {{.Brand}}.</p>
{{end}}<p style="margin:0 0 20px"><a ses:no-track href="{{.Link}}" style="display:inline-block;padding:12px 20px;background:#2f2f6b;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:700">{{if .Reset}}Choose a new password{{else}}Choose your password{{end}}</a></p>
<p style="margin:0 0 8px;font-size:14px;color:#5b6070">The link works once and expires {{.Expires}}. Then sign in at <a ses:no-track href="{{.SignInURL}}" style="color:#2f2f6b">{{.SignInURL}}</a>.</p>
<p style="margin:0;font-size:14px;color:#5b6070">{{if .Reset}}If you did not expect this email, tell your administrator.{{else}}If you were not expecting this email, you can ignore it: nothing happens unless the link is used.{{end}}</p>
</div>
</body>
</html>
`

var (
	textTmpl = texttemplate.Must(texttemplate.New("text").Parse(textBody))
	htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Parse(htmlBody))
)

// brandText is the brand name as the pages show it, Unicode included, with
// control characters (line breaks among them) removed and at most 64
// characters kept: it goes into the subject.
func brandText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		if n == 64 {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// render builds the email for a link of purpose. brand and baseURL come from
// configuration; link carries the token.
func render(purpose, brand, baseURL, link string, expires time.Time) (message, error) {
	brand = brandText(brand)
	if brand == "" {
		brand = "your organisation"
	}
	data := messageData{
		Brand:     brand,
		Link:      link,
		SignInURL: baseURL + "/",
		Expires:   expires.UTC().Format("Mon 2 Jan 2006 at 15:04 UTC"),
		Reset:     purpose == store.LinkReset,
	}
	var text, html strings.Builder
	if err := textTmpl.Execute(&text, data); err != nil {
		return message{}, err
	}
	if err := htmlTmpl.Execute(&html, data); err != nil {
		return message{}, err
	}
	subject := "Choose your " + brand + " password"
	if data.Reset {
		subject = "Your " + brand + " password was reset"
	}
	return message{Subject: subject, Text: text.String(), HTML: html.String()}, nil
}
