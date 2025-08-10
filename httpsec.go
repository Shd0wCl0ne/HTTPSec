// cmd: go run httpsec.go https://example.com
// or  : go run httpsec.go -ua "HTTPSec/1.0" -timeout 10s https://example.com
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	statusPass = "PASS"
	statusWarn = "WARN"
	statusFail = "FAIL"
	statusInfo = "INFO"
)

type Check struct {
	Name       string
	Status     string
	Detail     string
	Highlights []string // substrings inside Detail to colorize when WARN/FAIL
}

type cfgFlags struct {
	timeout     time.Duration
	userAgent   string
	insecureTLS bool
	maxRedirect int
	showHelp    bool
}

var (
	// ANSI colors
	reset     = "\x1b[0m"
	dim       = "\x1b[2m"
	bold      = "\x1b[1m"
	green     = "\x1b[32m"
	yellow    = "\x1b[33m"
	red       = "\x1b[31m"
	blue      = "\x1b[34m"
	gray      = "\x1b[90m"
	checkMark = green + "✔" + reset
	warnTri   = yellow + "▲" + reset
	failX     = red + "✘" + reset
	infoI     = blue + "i" + reset
)

func main() {
	cfg, target := parseFlags()
	if cfg.showHelp {
		printHelp()
		return
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, red+"error:"+reset+" no URL provided\n")
		printHelp()
		os.Exit(2)
	}

	raw := target
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		die("invalid URL: %v", err)
	}

	client := &http.Client{
		Timeout: cfg.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.insecureTLS}, // user opted in
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.maxRedirect && cfg.maxRedirect >= 0 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// First request: try HTTPS, then HTTP (for redirect tests)
	resHTTPS, httpsErr := fetch(client, u, cfg.userAgent)
	var resHTTP *http.Response
	var httpErr error

	uHTTP := *u
	uHTTP.Scheme = "http"
	if u.Scheme == "https" {
		resHTTP, httpErr = fetch(client, &uHTTP, cfg.userAgent)
	}

	// Build header map from the best response we have (prefer https)
	var baseRes *http.Response
	if resHTTPS != nil {
		baseRes = resHTTPS
	} else if resHTTP != nil {
		baseRes = resHTTP
	} else {
		die("request failed: https: %v, http: %v", httpsErr, httpErr)
	}
	defer func() {
		if resHTTPS != nil && resHTTPS.Body != nil {
			resHTTPS.Body.Close()
		}
		if resHTTP != nil && resHTTP.Body != nil {
			resHTTP.Body.Close()
		}
	}()

	headers := canonicalize(baseRes.Header)

	// Evaluate checks
	var checks []Check
	host := u.Hostname()
	title := fmt.Sprintf("== %s ==", raw)
	fmt.Println(bold + title + reset)

	// Left/right table layout
	// Compute widest left label for neat columns
	checks = append(checks, checkHTTPRedirect(resHTTP, httpsErr))
	checks = append(checks, checkHSTS(headers, host))
	checks = append(checks, checkXContentType(headers))
	checks = append(checks, checkXFrame(headers))
	checks = append(checks, checkXXSS(headers))
	checks = append(checks, checkReferrerPolicy(headers))
	checks = append(checks, checkXPermittedCrossDomainPolicies(headers))
	checks = append(checks, checkCOOP(headers))
	checks = append(checks, checkCOEP(headers))
	checks = append(checks, checkCORP(headers))
	checks = append(checks, checkPermissionsPolicy(headers))
	checks = append(checks, checkClearSiteData(headers))
	checks = append(checks, checkOriginAgentCluster(headers))
	checks = append(checks, checkReportingEndpoints(headers))
	checks = append(checks, checkCSP(headers))
	checks = append(checks, checkUpgradeInsecureRequests(headers))
	checks = append(checks, checkExpectCT(headers)) // deprecated

	// Print table
	nameW := 30
	for _, c := range checks {
		if len(c.Name)+2 > nameW {
			nameW = len(c.Name) + 2
		}
	}
	// Header row
	fmt.Println(dim + "Status  " + pad("Check", nameW) + "Details" + reset)

	for _, c := range checks {
		statusGlyph, _ := glyph(c.Status) // ignore color return

		// Color the vertical status word to match the horizontal summary
		coloredStatus := c.Status
		switch c.Status {
		case statusPass:
			coloredStatus = green + c.Status + reset
		case statusWarn:
			coloredStatus = yellow + c.Status + reset
		case statusFail:
			coloredStatus = red + c.Status + reset
		case statusInfo:
			coloredStatus = blue + c.Status + reset
		}

		left := fmt.Sprintf("%s %-5s", statusGlyph, coloredStatus)
		lineLeft := left + "  " + pad(c.Name, nameW)

		detail := c.Detail
		if (c.Status == statusWarn || c.Status == statusFail) && len(c.Highlights) > 0 {
			detail = highlight(detail, c.Highlights)
		}
		fmt.Printf("%s%s\n", lineLeft, detail)
	}


	// Summary
	var pass, warn, fail, info int
	for _, c := range checks {
		switch c.Status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
		case statusFail:
			fail++
		default:
			info++
		}
	}
	fmt.Printf("\nSummary: %s %d  %s %d  %s %d  %s %d\n",
		color(statusPass, statusPass), pass,
		color(statusWarn, statusWarn), warn,
		color(statusFail, statusFail), fail,
		color(statusInfo, statusInfo), info)
}

func parseFlags() (cfg cfgFlags, target string) {
	flag.Usage = printHelp
	flag.DurationVar(&cfg.timeout, "timeout", 8*time.Second, "request timeout (e.g. 10s, 2m)")
	flag.StringVar(&cfg.userAgent, "ua", "HTTPSec/1.0 (+https://github.com/your/HTTPSec)", "custom User-Agent")
	flag.BoolVar(&cfg.insecureTLS, "k", false, "allow insecure TLS (skip certificate verify)")
	flag.IntVar(&cfg.maxRedirect, "max-redirects", 10, "maximum redirects to follow (-1 no follow)")
	flag.BoolVar(&cfg.showHelp, "h", false, "show help")
	flag.BoolVar(&cfg.showHelp, "help", false, "show help")
	flag.Parse()
	if flag.NArg() > 0 {
		target = strings.TrimSpace(flag.Arg(0))
	}
	return
}

func printHelp() {
	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintln(w, bold+"HTTPSec - lightweight HTTP security header linter"+reset)
	fmt.Fprintln(w, "\nUsage:")
	fmt.Fprintln(w, "  go run httpsec.go [flags] <url>")
	fmt.Fprintln(w, "\nExamples:")
	fmt.Fprintln(w, "  go run httpsec.go https://public-firing-range.appspot.com")
	fmt.Fprintln(w, "  go run httpsec.go -ua 'HTTPSec/1.0' -timeout 10s https://example.com")
	fmt.Fprintln(w, "\nFlags:")
	fmt.Fprintln(w, "  -h, --help             Show this help")
	fmt.Fprintln(w, "  -timeout 10s           Request timeout")
	fmt.Fprintln(w, "  -ua 'HTTPSec/1.0'      Custom User-Agent")
	fmt.Fprintln(w, "  -k                     Allow insecure TLS (skip verify)")
	fmt.Fprintln(w, "  -max-redirects 10      Maximum redirects to follow (-1 no follow)")
	w.Flush()
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, red+"error:"+reset+" "+f+"\n", a...)
	os.Exit(1)
}

func fetch(client *http.Client, u *url.URL, ua string) (*http.Response, error) {
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	return client.Do(req)
}

func canonicalize(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		key := http.CanonicalHeaderKey(k)
		out[key] = strings.Join(v, ", ")
	}
	return out
}

func hasToken(val string, wanted string) bool {
	// token match case-insensitive, semicolon or space separated
	re := regexp.MustCompile(`(?i)(^|[;,\s])` + regexp.QuoteMeta(wanted) + `($|[;,\s=])`)
	return re.FindStringIndex(val) != nil
}

func splitDirectives(s string) map[string]string {
	parts := strings.Split(s, ";")
	m := map[string]string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			m[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		} else {
			m[strings.ToLower(p)] = ""
		}
	}
	return m
}

// Checks

func checkHTTPRedirect(resHTTP *http.Response, httpsErr error) Check {
	name := "HTTP➜HTTPS Redirect"
	if resHTTP == nil {
		// If we couldn't fetch HTTP, mark INFO unless error is clearly not found
		return Check{name, statusInfo, "could not verify (HTTP not fetched)", nil}
	}
	loc, _ := resHTTP.Location()
	if resHTTP.StatusCode >= 300 && resHTTP.StatusCode < 400 && loc != nil && strings.HasPrefix(strings.ToLower(loc.String()), "https://") {
		return Check{name, statusInfo, "fetched over HTTP - did not verify HTTP origin", nil}
	}
	// If server serves HTTP content or redirects to HTTP
	return Check{name, statusInfo, "fetched over HTTPS - did not verify HTTP origin", nil}
}

func checkHSTS(h map[string]string, host string) Check {
	name := "HSTS"
	val, ok := h["Strict-Transport-Security"]
	if !ok {
		return Check{name, statusWarn, "missing", []string{"missing"}}
	}
	d := splitDirectives(val)
	var hi []string
	var issues []string
	status := statusPass

	// max-age
	max, hasMax := d["max-age"]
	if !hasMax {
		status = statusFail
		issues = append(issues, "missing max-age")
		hi = append(hi, "max-age")
	} else {
		// best practice: >= 63072000 (2 years)
		// treat non-numeric or low values as WARN
		numeric := regexp.MustCompile(`^\d+$`).MatchString(max)
		if !numeric {
			status = statusFail
			issues = append(issues, "invalid max-age="+max)
			hi = append(hi, "max-age="+max)
		} else {
			// length check
			if len(max) > 0 {
				// parse manually to avoid strconv import weight
				// simple lexical: any >= 63072000 flagged ok; otherwise warn
				if lt(max, "63072000") {
					if status != statusFail {
						status = statusWarn
					}
					issues = append(issues, "low max-age="+max+" (recommend ≥63072000)")
					hi = append(hi, "max-age="+max)
				}
			}
		}
	}

	// includeSubDomains
	_, hasISD := d["includesubdomains"]
	if !hasISD {
		// also catch "includeSubDomains=false" anti-pattern
		if strings.Contains(strings.ToLower(val), "includesubdomains=false") {
			status = statusWarn
			issues = append(issues, "(includeSubDomains=false)")
			hi = append(hi, "includeSubDomains=false")
		} else {
			status = statusWarn
			issues = append(issues, "(includeSubDomains missing)")
			hi = append(hi, "includeSubDomains")
		}
	}

	// preload advisory
	if _, ok := d["preload"]; !ok {
		issues = append(issues, "preload not set (optional)")
	}

	detail := buildHSTSDetail(max, hasMax, hasISD, d)
	if len(issues) > 0 {
		detail = detail + "  " + strings.Join(issues, "; ")
	}
	return Check{name, status, detail, hi}
}

func buildHSTSDetail(max string, hasMax, hasISD bool, d map[string]string) string {
	var bits []string
	if hasMax {
		bits = append(bits, "max-age="+max)
	} else {
		bits = append(bits, "max-age")
	}
	if hasISD {
		bits = append(bits, "includeSubDomains")
	}
	if _, ok := d["preload"]; ok {
		bits = append(bits, "preload")
	}
	return strings.Join(bits, "; ")
}

func checkXContentType(h map[string]string) Check {
	name := "X-Content-Type-Options"
	val, ok := h["X-Content-Type-Options"]
	if !ok {
		return Check{name, statusFail, "missing or not 'nosniff'", []string{"missing", "not 'nosniff'"}}
	}
	if strings.EqualFold(strings.TrimSpace(val), "nosniff") {
		return Check{name, statusPass, "nosniff", nil}
	}
	return Check{name, statusFail, "value="+val+" (expect 'nosniff')", []string{val}}
}

func checkXFrame(h map[string]string) Check {
	name := "X-Frame-Options"
	val, ok := h["X-Frame-Options"]
	if !ok {
		return Check{name, statusWarn, "missing (prefer CSP frame-ancestors)", []string{"missing"}}
	}
	v := strings.ToUpper(strings.TrimSpace(val))
	if v == "DENY" || v == "SAMEORIGIN" {
		return Check{name, statusPass, v + " (note: prefer CSP frame-ancestors)", nil}
	}
	// ALLOW-FROM is obsolete
	return Check{name, statusWarn, "non-standard: " + v + " (prefer CSP frame-ancestors)", []string{v}}
}

func checkXXSS(h map[string]string) Check {
	name := "X-XSS-Protection"
	val, ok := h["X-XSS-Protection"]
	if !ok {
		return Check{name, statusInfo, "disabled or absent (deprecated header)", nil}
	}
	return Check{name, statusInfo, "present: " + val + " (deprecated header)", nil}
}

func checkReferrerPolicy(h map[string]string) Check {
	name := "Referrer-Policy"
	val, ok := h["Referrer-Policy"]
	if !ok {
		return Check{name, statusWarn, "missing", []string{"missing"}}
	}
	v := strings.ToLower(strings.TrimSpace(val))
	// good: no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin
	good := map[string]bool{
		"no-referrer":                       true,
		"same-origin":                       true,
		"strict-origin":                     true,
		"strict-origin-when-cross-origin":   true,
	}
	if good[v] {
		return Check{name, statusPass, v, nil}
	}
	// weak values to highlight
	weak := []string{"no-referrer-when-downgrade", "unsafe-url", "origin", "origin-when-cross-origin"}
	hi := []string{}
	for _, w := range weak {
		if strings.Contains(v, w) {
			hi = append(hi, w)
		}
	}
	if len(hi) == 0 {
		hi = append(hi, v)
	}
	return Check{name, statusWarn, v + " (consider 'strict-origin-when-cross-origin')", hi}
}

func checkXPermittedCrossDomainPolicies(h map[string]string) Check {
	name := "X-Permitted-Cross-Domain-Policies"
	val, ok := h["X-Permitted-Cross-Domain-Policies"]
	if !ok {
		return Check{name, statusWarn, "missing (set to 'none' unless needed)", []string{"missing"}}
	}
	v := strings.ToLower(strings.TrimSpace(val))
	if v == "none" {
		return Check{name, statusPass, "none", nil}
	}
	// show value; highlight if overly permissive
	if v == "all" || v == "master-only" || v == "by-content-type" || v == "by-ftp-filename" {
		return Check{name, statusWarn, v + " (set to 'none' unless needed)", []string{v}}
	}
	return Check{name, statusWarn, val + " (review)", []string{val}}
}

func checkCOOP(h map[string]string) Check {
	name := "COOP"
	val, ok := h["Cross-Origin-Opener-Policy"]
	if !ok {
		return Check{name, statusWarn, "missing (recommend same-origin)", []string{"missing"}}
	}
	v := strings.ToLower(strings.TrimSpace(val))
	if v == "same-origin" {
		return Check{name, statusPass, v, nil}
	}
	return Check{name, statusWarn, v + " (recommend same-origin for stronger isolation)", []string{v}}
}

func checkCOEP(h map[string]string) Check {
	name := "COEP"
	val, ok := h["Cross-Origin-Embedder-Policy"]
	if !ok {
		return Check{name, statusWarn, "missing (recommend require-corp)", []string{"missing"}}
	}
	v := strings.ToLower(strings.TrimSpace(val))
	if v == "require-corp" || v == "credentialless" {
		// pass with info note
		return Check{name, statusPass, v, nil}
	}
	return Check{name, statusWarn, v + " (recommend require-corp)", []string{v}}
}

func checkCORP(h map[string]string) Check {
	name := "CORP"
	val, ok := h["Cross-Origin-Resource-Policy"]
	if !ok {
		return Check{name, statusWarn, "missing - set based on asset exposure (same-origin|same-site|cross-origin)", []string{"missing"}}
	}
	v := strings.ToLower(strings.TrimSpace(val))
	switch v {
	case "same-origin", "same-site", "cross-origin":
		// same-site or same-origin is typically better
		if v == "cross-origin" {
			return Check{name, statusWarn, v + " (tighten if possible)", []string{v}}
		}
		return Check{name, statusPass, v, nil}
	default:
		return Check{name, statusWarn, v + " (review)", []string{v}}
	}
}

func checkPermissionsPolicy(h map[string]string) Check {
	name := "Permissions-Policy"
	val, ok := h["Permissions-Policy"]
	if !ok {
		return Check{name, statusWarn, "missing - disable sensitive features by default", []string{"missing"}}
	}
	// Quick heuristics: flag broad allowlists like "*", or "(self)" without empty "()"
	// Highlight dangerous patterns
	hi := []string{}
	lc := strings.ToLower(val)
	if strings.Contains(lc, "=(") && strings.Contains(lc, "*") {
		hi = append(hi, "*")
	}
	// Example highlight: geolocation=(self)
	if strings.Contains(lc, "geolocation=(") && !strings.Contains(lc, "geolocation=()") {
		hi = append(hi, "geolocation=(self)")
	}
	status := statusPass
	detail := val
	if len(hi) > 0 {
		status = statusWarn
		detail = val + " (review broad allows)"
	}
	return Check{name, status, detail, hi}
}

func checkClearSiteData(h map[string]string) Check {
	name := "Clear-Site-Data"
	val, ok := h["Clear-Site-Data"]
	if !ok {
		return Check{name, statusInfo, "not present on this response - typically used on logout", nil}
	}
	return Check{name, statusInfo, "present: " + val, nil}
}

func checkOriginAgentCluster(h map[string]string) Check {
	name := "Origin-Agent-Cluster"
	val, ok := h["Origin-Agent-Cluster"]
	if !ok {
		return Check{name, statusInfo, "optional - consider '?1' for stronger isolation", nil}
	}
	if strings.TrimSpace(val) == "?1" {
		return Check{name, statusInfo, val, nil}
	}
	return Check{name, statusInfo, "present: " + val, nil}
}

func checkReportingEndpoints(h map[string]string) Check {
	name := "Reporting-Endpoints"
	val1, ok1 := h["Reporting-Endpoints"]
	val2, ok2 := h["Report-To"] // legacy
	if ok1 {
		return Check{name, statusInfo, "configured: " + val1, nil}
	}
	if ok2 {
		return Check{name, statusInfo, "legacy Report-To present: " + val2, nil}
	}
	return Check{name, statusInfo, "not configured (optional)", nil}
}

func checkCSP(h map[string]string) Check {
	name := "CSP"
	val, ok := h["Content-Security-Policy"]
	if !ok {
		return Check{name, statusFail, "missing", []string{"missing"}}
	}
	lc := strings.ToLower(val)
	hi := []string{}
	if strings.Contains(lc, "unsafe-inline") {
		hi = append(hi, "'unsafe-inline'")
	}
	if strings.Contains(lc, "unsafe-eval") {
		hi = append(hi, "'unsafe-eval'")
	}
	// default-src must exist
	if !hasToken(lc, "default-src") {
		hi = append(hi, "default-src")
	}
	status := statusPass
	detail := val
	if len(hi) > 0 {
		status = statusWarn
		detail = val + "  (avoid 'unsafe-*'; define default-src)"
	}
	return Check{name, status, detail, hi}
}

func checkUpgradeInsecureRequests(h map[string]string) Check {
	name := "Upgrade-Insecure-Requests"
	_, ok := h["Upgrade-Insecure-Requests"]
	if !ok {
		return Check{name, statusInfo, "not configured (optional)", nil}
	}
	return Check{name, statusInfo, "present", nil}
}

func checkExpectCT(h map[string]string) Check {
	name := "Expect-CT"
	_, ok := h["Expect-CT"]
	if !ok {
		return Check{name, statusInfo, "not present (fine - deprecated)", nil}
	}
	return Check{name, statusInfo, "present (deprecated)", nil}
}

// Utilities

func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func glyph(status string) (string, string) {
	switch status {
	case statusPass:
		return checkMark, green
	case statusWarn:
		return warnTri, yellow
	case statusFail:
		return failX, red
	default:
		return infoI, blue
	}
}

func color(kind, s string) string {
	switch kind {
	case statusPass:
		return green + s + reset
	case statusWarn:
		return yellow + s + reset
	case statusFail:
		return red + s + reset
	case statusInfo:
		return blue + s + reset
	default:
		return s
	}
}

func highlight(text string, tokens []string) string {
	// Dedup and longest-first to avoid partial overlaps
	uniq := map[string]struct{}{}
	for _, t := range tokens {
		if t == "" {
			continue
		}
		uniq[t] = struct{}{}
	}
	list := make([]string, 0, len(uniq))
	for t := range uniq {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	out := text
	for _, t := range list {
		// Case-insensitive replace but preserve original chunk casing via regex
		// Wrap bad parts in bright red
		re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(t))
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			return red + m + reset
		})
	}
	return out
}

// naive string numeric compare for positive integers as strings (no leading +/-, no spaces)
func lt(a, b string) bool {
	// remove leading zeros for fair length compare
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) == 0 {
		a = "0"
	}
	if len(b) == 0 {
		b = "0"
	}
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}
