package httpapi

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed locales/*.json
var localeFS embed.FS

var languageCatalogs = loadLanguageCatalogs()
var messageSlot = regexp.MustCompile(`\{([0-9]+)\}`)

// Parsed templates and their locale closures are immutable; reuse them across
// server instances instead of parsing every language again for each fixture.
var compiledTemplates = sync.OnceValue(func() map[string]*template.Template {
	return map[string]*template.Template{
		"en": parseTemplates(), "es": localizedTemplates("es"), "pt": localizedTemplates("pt"),
	}
})

func loadLanguageCatalogs() map[string]map[string]string {
	catalogs := map[string]map[string]string{"en": {}}
	for _, lang := range []string{"es", "pt"} {
		raw, err := localeFS.ReadFile("locales/" + lang + ".json")
		if err != nil {
			panic(err)
		}
		var catalog map[string]string
		if err := json.Unmarshal(raw, &catalog); err != nil {
			panic(err)
		}
		catalogs[lang] = catalog
	}
	return catalogs
}

func normalizeLanguage(raw string) string {
	switch lang := strings.SplitN(strings.ToLower(strings.TrimSpace(raw)), "-", 2)[0]; lang {
	case "en":
		return "en"
	case "es":
		return "es"
	case "pt":
		return "pt"
	default:
		return ""
	}
}

func translate(lang, source string, values ...any) string {
	message := source
	if translated, ok := languageCatalogs[lang][source]; ok {
		message = translated
	}
	return messageSlot.ReplaceAllStringFunc(message, func(slot string) string {
		index, _ := strconv.Atoi(slot[1 : len(slot)-1])
		if index >= len(values) {
			return slot
		}
		return displayNumber(values[index], lang)
	})
}

func requestLanguage(r *http.Request) string {
	if lang := normalizeLanguage(r.URL.Query().Get("lang")); lang != "" {
		return lang
	}
	// OIDC UI preference is display-only: never rewrite redirect_uri, state,
	// authorization codes or the relying application's callback parameters.
	for _, value := range strings.Fields(r.URL.Query().Get("ui_locales")) {
		if lang := normalizeLanguage(value); lang != "" {
			return lang
		}
	}
	if saved, err := r.Cookie("elcano_language"); err == nil {
		if lang := normalizeLanguage(saved.Value); lang != "" {
			return lang
		}
	}
	type preference struct {
		lang    string
		quality float64
	}
	var preferences []preference
	for _, value := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		parts := strings.Split(strings.TrimSpace(value), ";")
		lang := normalizeLanguage(parts[0])
		quality := 1.0
		for _, param := range parts[1:] {
			if q, ok := strings.CutPrefix(strings.TrimSpace(param), "q="); ok {
				if parsed, err := strconv.ParseFloat(q, 64); err == nil {
					quality = parsed
				} else {
					quality = 0
				}
			}
		}
		if lang != "" && quality > 0 && quality <= 1 {
			preferences = append(preferences, preference{lang, quality})
		}
	}
	sort.SliceStable(preferences, func(i, j int) bool { return preferences[i].quality > preferences[j].quality })
	if len(preferences) != 0 {
		return preferences[0].lang
	}
	return "en"
}

type languageWriter struct {
	http.ResponseWriter
	language  string
	query     url.Values
	canChange bool
}

func (w *languageWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) withLanguage(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := requestLanguage(r)
		explicit := normalizeLanguage(r.URL.Query().Get("lang")) != ""
		for _, locale := range strings.Fields(r.URL.Query().Get("ui_locales")) {
			explicit = explicit || normalizeLanguage(locale) != ""
		}
		if explicit && !strings.HasPrefix(r.URL.Path, "/assets/") && !strings.HasPrefix(r.URL.Path, "/brand/") {
			http.SetCookie(w, &http.Cookie{Name: "elcano_language", Value: lang, Path: "/", MaxAge: 31536000, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		}
		next.ServeHTTP(&languageWriter{ResponseWriter: w, language: lang, query: s.languageQuery(r), canChange: r.Method == http.MethodGet}, r)
	})
}

func languageOf(w http.ResponseWriter) string {
	if localized, ok := w.(*languageWriter); ok {
		return localized.language
	}
	return "en"
}

func localizedTemplates(lang string) *template.Template {
	return template.Must(template.New("").Funcs(template.FuncMap{
		"asset": assetURL,
		"helpAsset": func(name string) (string, error) {
			if lang != "en" {
				name = lang + "/" + name
			}
			return assetURL("help/" + name)
		},
		"tr":       func(source string, values ...any) string { return translate(lang, source, values...) },
		"language": func() string { return lang },
		"number":   func(value any) string { return displayNumber(value, lang) },
	}).ParseFS(templateFS, "templates/*.html"))
}

func selectedLanguage(languages []string) string {
	if len(languages) != 0 && normalizeLanguage(languages[0]) != "" {
		return normalizeLanguage(languages[0])
	}
	return "en"
}

func displayDate(value time.Time, language string, clock bool) string {
	layout := "2006-01-02"
	if language == "es" || language == "pt" {
		layout = "02/01/2006"
	}
	if clock {
		layout += " 15:04"
	}
	return value.UTC().Format(layout)
}

// The language form carries only validated navigation state. In particular,
// err is a closed code set, never attacker-provided prose, and return_to keeps
// exactly the same allowlist as the sign-in flow.
func (s *Server) languageQuery(r *http.Request) url.Values {
	query := r.URL.Query()
	out := url.Values{}
	if value := s.resolveReturnTo(query.Get("return_to")); value != "" {
		out.Set("return_to", value)
	}
	if code := query.Get("err"); errorMessage(code) != "" {
		out.Set("err", code)
	}
	if code := query.Get("notice"); s.noticeMessage(code) != "" {
		out.Set("notice", code)
	}
	switch r.URL.Path {
	case "/sent":
		out.Set("email", query.Get("email"))
	case "/admin":
		out.Set("tab", query.Get("tab"))
	case "/account/security", "/account/security/verify":
		if action := query.Get("action"); securityActions[action] {
			out.Set("action", action)
		}
		if r.URL.Path == "/account/security" && query.Get("verified") == "1" {
			out.Set("verified", "1")
		}
	case "/login/verify":
		if query.Get("mode") == "recovery" {
			out.Set("mode", "recovery")
		}
	case "/authorize":
		// An HTML response here is reached only after the OAuth request is
		// validated. Changing presentation must preserve every protocol value.
		for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
			for _, value := range query[key] {
				out.Add(key, value)
			}
		}
	}
	return out
}

// Counts are presentation values; opaque strings such as codes remain untouched.
func displayNumber(value any, language string) string {
	switch value.(type) {
	case int, int64, int32, uint, uint64, uint32:
	default:
		return fmt.Sprint(value)
	}
	digits := fmt.Sprint(value)
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	if len(digits) <= 3 || (language == "es" && len(digits) == 4) {
		return sign + digits
	}
	separator := ","
	if language == "es" {
		separator = "."
	}
	if language == "pt" {
		separator = "\u00a0"
	}
	var groups []string
	for len(digits) > 3 {
		groups = append([]string{digits[len(digits)-3:]}, groups...)
		digits = digits[:len(digits)-3]
	}
	return sign + strings.Join(append([]string{digits}, groups...), separator)
}
