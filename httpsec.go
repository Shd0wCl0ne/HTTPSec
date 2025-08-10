// httpsec - lightweight HTTP security headers checker (pretty CLI)
// Run: go run httpsec
// Run:   ./httpsec https://example.com
// JSON:  ./httpsec -json https://example.com
// List:  ./httpsec -f targets.txt -workers 8 -ci warn
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	PASS = "PASS"
	WARN = "WARN"
	FAIL = "FAIL"
	INFO = "INFO"
)

var (
	// flags
	outJSON    = flag.Bool("json", false, "output JSON")
	timeout    = flag.Duration("timeout", 10*time.Second, "HTTP timeout")
	insecure   = flag.Bool("insecure", false, "allow insecure TLS")
	userAgent  = flag.String("ua", "httpsec/1.1", "user-agent")
	fileList   = flag.String("f", "", "path to file with URLs (one per line)")
	workers    = flag.Int("workers", 4, "concurrent workers for multiple URLs")
	ciLevel    = flag.String("ci", "off", "exit non-zero if any: off|warn|fail")
	probeBoth  = flag.Bool("probe-both", false, "when URL is https, also probe http:// origin for redirect/HSTS")
	method     = flag.String("X", "GET", "HTTP method to use (GET/HEAD)")
	showHelp   = flag.Bool("h", false, "show help")
	showHelp2  = flag.Bool("help", false, "show help")
	headerKVs  headerFlags
	versionStr = "1.1.0"
)

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ",") }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type Check struct {
	Item   string      `json:"item"`
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Extra  interface{} `json:"extra,omitempty"`
}

type Report struct {
	Target     string   `json:"target"`
	FinalURL   string   `json:"final_url"`
	HTTPS      bool     `json:"https"`
	Checks     []Check  `json:"checks"`
	Redirected bool     `json:"redirected"`
	History    []string `json:"history,omitempty"`
	Summary    Summary  `json:"summary"`
}

type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Info int `json:"info"`
}

func init() {
	flag.Var(&headerKVs, "H", "extra request header, repeatable (e.g. -H 'Cookie: a=b')")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, `
httpsec v%s - HTTP security headers checker

Usage:
  httpsec [flags] <url ...>
  httpsec [flags] -f urls.txt

Examples:
  httpsec https://example.com
  httpsec -probe-both https://example.com
  httpsec -f urls.txt -workers 8 -ci warn
  httpsec -json https://site1 https://site2
  httpsec -H "Cookie: session=xyz" https://intranet.local

Key flags:
  -ci           Exit non-zero if any issues: off|warn|fail
  -probe-both   When target is https, also probe http:// for redirect/HSTS
  -json         Emit JSON instead of pretty text
  -f FILE       Read URLs from file
  -workers N    Concurrency for multiple targets

Other flags:
`, versionStr)
	flag.PrintDefaults()
}

func main() {
	flag.Parse()
	if *showHelp || *showHelp2 {
		usage()
		return
	}
	var targets []string
	if *fileList != "" {
		lines, err := readLines(*fileList)
		if err != nil {
			fatal("read list: %v", err)
		}
		targets = append(targets, lines...)
	}
	targets = append(targets, flag.Args()...)
	if len(targets) == 0 {
		usage()
		os.Exit(2)
	}

	// de-dup
	seen := map[string]bool{}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !strings.Contains(t, "://") {
			// default to https if no scheme provided
			t = "https://" + t
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	targets = out

	// multi or single
	if len(targets) == 1 {
		rep := scanTarget(targets[0])
		if *outJSON {
			jsonOut(rep)
		} else {
			printPretty(rep)
		}
		exitByCI(rep)
		return
	}

	// pool
	type res struct {
		rep Report
		err error
	}
	jobs := make(chan string)
	results := make(chan res)
	wg := sync.WaitGroup{}
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				r := scanTarget(t)
				results <- res{rep: r}
			}
		}()
	}
	go func() {
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var all []Report
	for r := range results {
		all = append(all, r.rep)
	}

	// deterministic order
	sort.Slice(all, func(i, j int) bool { return all[i].Target < all[j].Target })

	rc := 0
	if *outJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(all)
	} else {
		for i, rep := range all {
			if i > 0 {
				fmt.Println()
			}
			printPretty(rep)
		}
	}
	// CI exit - if any report violates threshold
	for _, rep := range all {
		rc = max(rc, ciExitCode(rep))
	}
	os.Exit(rc)
}

// -------- scanning ----------

func scanTarget(target string) Report {
	// primary scan
	rep := run(target)

	// optional http probe if initial was https
	if *probeBoth {
		u, _ := url.Parse(target)
		if u != nil && u.Scheme == "https" && u.Host != "" {
			u2 := *u
			u2.Scheme = "http"
			// only add an extra check, do not replace primary
			rep2 := run(u2.String())
			mergeHTTPProbe(&rep, &rep2)
		}
	}
	rep.Summary = summarize(rep.Checks)
	return rep
}

func run(target string) Report {
	report := Report{Target: target}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		report.Checks = append(report.Checks, Check{"Reachability", FAIL, "invalid URL or missing http(s) scheme", nil})
		return report
	}

	client, history := newClientWithHistory()
	client.Timeout = *timeout
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}, // scanner setting
		Proxy:           http.ProxyFromEnvironment,
	}

	req, _ := http.NewRequestWithContext(context.Background(), strings.ToUpper(*method), target, nil)
	req.Header.Set("User-Agent", *userAgent)
	for _, kv := range headerKVs {
		if p := strings.Index(kv, ":"); p > 0 {
			k := strings.TrimSpace(kv[:p])
			v := strings.TrimSpace(kv[p+1:])
			if k != "" {
				req.Header.Add(k, v)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		report.Checks = append(report.Checks, Check{"Reachability", FAIL, err.Error(), nil})
		return report
	}
	defer resp.Body.Close()

	report.FinalURL = resp.Request.URL.String()
	report.HTTPS = resp.Request.URL.Scheme == "https"
	report.Redirected = len(*history) > 0
	if len(*history) > 0 {
		report.History = append(report.History, *history...)
	}

	// explicit HTTP->HTTPS check if caller asked with http
	if parsed.Scheme == "http" {
		if report.HTTPS {
			report.Checks = append(report.Checks, Check{"HTTP→HTTPS Redirect", PASS, "HTTP redirected to HTTPS", nil})
		} else {
			report.Checks = append(report.Checks, Check{"HTTP→HTTPS Redirect", FAIL, "no redirect to HTTPS", nil})
		}
	} else if report.HTTPS {
		report.Checks = append(report.Checks, Check{"HTTP→HTTPS Redirect", INFO, "fetched over HTTPS - did not verify HTTP origin", nil})
	}

	h := normalize(resp.Header)

	// HSTS
	if report.HTTPS {
		hsts := h.Get("strict-transport-security")
		if hsts == "" {
			report.Checks = append(report.Checks, Check{"HSTS", FAIL, "missing on HTTPS response", nil})
		} else {
			maxAge := parseMaxAge(hsts)
			hasISD := containsFold(hsts, "includeSubDomains")
			hasPreload := containsFold(hsts, "preload")
			status := WARN
			if maxAge >= 15552000 && hasISD { // 180 days
				status = PASS
			}
			msg := fmt.Sprintf("max-age=%d; includeSubDomains=%t; preload=%t", maxAge, hasISD, hasPreload)
			report.Checks = append(report.Checks, Check{"HSTS", status, msg, map[string]string{"raw": hsts}})
		}
	} else {
		report.Checks = append(report.Checks, Check{"HSTS", INFO, "skip - final URL not HTTPS", nil})
	}

	// X-Content-Type-Options
	if val := strings.ToLower(h.Get("x-content-type-options")); val == "nosniff" {
		report.Checks = append(report.Checks, Check{"X-Content-Type-Options", PASS, "nosniff", nil})
	} else {
		report.Checks = append(report.Checks, Check{"X-Content-Type-Options", FAIL, "missing or not 'nosniff'", nil})
	}

	// X-Frame-Options
	if v := strings.ToLower(h.Get("x-frame-options")); v != "" {
		switch v {
		case "deny", "sameorigin":
			report.Checks = append(report.Checks, Check{"X-Frame-Options", PASS, v, nil})
		default:
			report.Checks = append(report.Checks, Check{"X-Frame-Options", WARN, "non standard value: " + v, nil})
		}
	} else {
		report.Checks = append(report.Checks, Check{"X-Frame-Options", WARN, "missing (prefer CSP frame-ancestors)", nil})
	}

	// X-XSS-Protection
	if v := strings.TrimSpace(h.Get("x-xss-protection")); v == "" || v == "0" {
		report.Checks = append(report.Checks, Check{"X-XSS-Protection", PASS, "disabled or absent (deprecated header)", nil})
	} else {
		report.Checks = append(report.Checks, Check{"X-XSS-Protection", WARN, "legacy setting present: " + v, nil})
	}

	// Referrer-Policy
	if v := strings.ToLower(h.Get("referrer-policy")); v != "" {
		switch v {
		case "no-referrer", "strict-origin-when-cross-origin":
			report.Checks = append(report.Checks, Check{"Referrer-Policy", PASS, v, nil})
		default:
			report.Checks = append(report.Checks, Check{"Referrer-Policy", WARN, v, nil})
		}
	} else {
		report.Checks = append(report.Checks, Check{"Referrer-Policy", FAIL, "missing", nil})
	}

	// X-Permitted-Cross-Domain-Policies
	if v := strings.ToLower(h.Get("x-permitted-cross-domain-policies")); v != "" {
		if v == "none" {
			report.Checks = append(report.Checks, Check{"X-Permitted-Cross-Domain-Policies", PASS, v, nil})
		} else {
			report.Checks = append(report.Checks, Check{"X-Permitted-Cross-Domain-Policies", WARN, v, nil})
		}
	} else {
		report.Checks = append(report.Checks, Check{"X-Permitted-Cross-Domain-Policies", WARN, "missing (set to 'none' unless needed)", nil})
	}

	// COOP
	if v := strings.ToLower(h.Get("cross-origin-opener-policy")); v == "same-origin" {
		report.Checks = append(report.Checks, Check{"COOP", PASS, v, nil})
	} else if v != "" {
		report.Checks = append(report.Checks, Check{"COOP", WARN, v + " (recommend same-origin)", nil})
	} else {
		report.Checks = append(report.Checks, Check{"COOP", WARN, "missing (recommend same-origin)", nil})
	}

	// COEP
	if v := strings.ToLower(h.Get("cross-origin-embedder-policy")); v == "require-corp" {
		report.Checks = append(report.Checks, Check{"COEP", PASS, v, nil})
	} else if v != "" {
		report.Checks = append(report.Checks, Check{"COEP", WARN, v + " (recommend require-corp)", nil})
	} else {
		report.Checks = append(report.Checks, Check{"COEP", WARN, "missing (recommend require-corp)", nil})
	}

	// CORP
	if v := strings.ToLower(h.Get("cross-origin-resource-policy")); v != "" {
		switch v {
		case "same-origin", "same-site", "cross-origin":
			report.Checks = append(report.Checks, Check{"CORP", PASS, v, nil})
		default:
			report.Checks = append(report.Checks, Check{"CORP", WARN, "unrecognized value: " + v, nil})
		}
	} else {
		report.Checks = append(report.Checks, Check{"CORP", WARN, "missing - set based on asset exposure", nil})
	}

	// Permissions-Policy
	if v := h.Get("permissions-policy"); v != "" {
		if strings.Contains(v, "*") {
			report.Checks = append(report.Checks, Check{"Permissions-Policy", WARN, "contains wildcard '*'. prefer explicit empty allowlists ()", map[string]string{"raw": v}})
		} else {
			report.Checks = append(report.Checks, Check{"Permissions-Policy", PASS, "present", map[string]string{"raw": v}})
		}
	} else {
		report.Checks = append(report.Checks, Check{"Permissions-Policy", WARN, "missing. disable sensitive features by default", nil})
	}

	// Clear-Site-Data
	if v := h.Get("clear-site-data"); v != "" {
		toks := tokenizeCSV(v)
		ok := containsStr(toks, "cookies") && containsStr(toks, "storage") && containsStr(toks, "cache")
		status := WARN
		if ok {
			status = PASS
		}
		report.Checks = append(report.Checks, Check{"Clear-Site-Data", status, v + " (ensure sent on logout endpoints)", nil})
	} else {
		report.Checks = append(report.Checks, Check{"Clear-Site-Data", INFO, "not present on this response - typically used on logout", nil})
	}

	// Origin-Agent-Cluster
	if v := strings.TrimSpace(h.Get("origin-agent-cluster")); v != "" {
		if v == "?1" {
			report.Checks = append(report.Checks, Check{"Origin-Agent-Cluster", PASS, v, nil})
		} else {
			report.Checks = append(report.Checks, Check{"Origin-Agent-Cluster", WARN, v + " (recommend ?1)", nil})
		}
	} else {
		report.Checks = append(report.Checks, Check{"Origin-Agent-Cluster", INFO, "optional - consider '?1' for stronger isolation", nil})
	}

	// Reporting-Endpoints (and CSP report-to linkage)
	reHdr := h.Get("reporting-endpoints")
	var groups map[string]string
	if reHdr != "" {
		groups = parseReportingEndpoints(reHdr)
		if len(groups) == 0 {
			report.Checks = append(report.Checks, Check{"Reporting-Endpoints", WARN, "malformed value", map[string]string{"raw": reHdr}})
		} else {
			report.Checks = append(report.Checks, Check{"Reporting-Endpoints", PASS, fmt.Sprintf("%d endpoint(s)", len(groups)), groups})
		}
	} else {
		report.Checks = append(report.Checks, Check{"Reporting-Endpoints", INFO, "not configured (optional)", nil})
	}

	// Upgrade-Insecure-Requests (response header is non standard)
	if v := h.Get("upgrade-insecure-requests"); v != "" {
		report.Checks = append(report.Checks, Check{"Upgrade-Insecure-Requests", WARN, "response header is non standard - prefer CSP directive", map[string]string{"raw": v}})
	}

	// CSP (and CSP-Report-Only)
	cspVals := h.Values("content-security-policy")
	cspRO := h.Values("content-security-policy-report-only")
	if len(cspVals) == 0 {
		report.Checks = append(report.Checks, Check{"CSP", FAIL, "missing", nil})
	} else {
		joined := strings.Join(cspVals, ", ")
		findings := lintCSP(joined)
		if len(findings) == 0 {
			report.Checks = append(report.Checks, Check{"CSP", PASS, "looks good", map[string]string{"raw": joined}})
		} else {
			report.Checks = append(report.Checks, Check{"CSP", WARN, strings.Join(findings, " ; "), map[string]string{"raw": joined}})
		}
		// report-to linkage
		if groups != nil {
			if rt := cspDirective(joined, "report-to"); rt != "" {
				if _, ok := groups[rt]; ok {
					report.Checks = append(report.Checks, Check{"CSP report-to", PASS, "group '" + rt + "' defined in Reporting-Endpoints", nil})
				} else {
					report.Checks = append(report.Checks, Check{"CSP report-to", WARN, "group '" + rt + "' not found in Reporting-Endpoints", nil})
				}
			}
		}
	}
	if len(cspRO) > 0 {
		joined := strings.Join(cspRO, ", ")
		findings := lintCSP(joined)
		status := INFO
		msg := "present"
		if len(findings) > 0 {
			status = INFO
			msg = "present; lint: " + strings.Join(findings, " ; ")
		}
		report.Checks = append(report.Checks, Check{"CSP-Report-Only", status, msg, map[string]string{"raw": joined}})
	}

	// Expect-CT
	if v := h.Get("expect-ct"); v != "" {
		report.Checks = append(report.Checks, Check{"Expect-CT", INFO, "obsolete header present - safe to remove", map[string]string{"raw": v}})
	} else {
		report.Checks = append(report.Checks, Check{"Expect-CT", INFO, "not present (fine - deprecated)", nil})
	}

	return report
}

// ---------- helpers ----------

func normalize(h http.Header) http.Header {
	n := http.Header{}
	for k, vals := range h {
		lk := strings.ToLower(k)
		for _, v := range vals {
			n.Add(lk, strings.TrimSpace(v))
		}
	}
	return n
}

func parseMaxAge(hsts string) int {
	re := regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
	m := re.FindStringSubmatch(hsts)
	if len(m) == 2 {
		var v int
		fmt.Sscanf(m[1], "%d", &v)
		return v
	}
	return 0
}

func lintCSP(csp string) []string {
	parts := strings.Split(csp, ";")
	dir := map[string]string{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ws := strings.Fields(p)
		k := strings.ToLower(ws[0])
		dir[k] = strings.Join(ws[1:], " ")
	}
	var f []string
	if _, ok := dir["default-src"]; !ok {
		f = append(f, "missing default-src")
	}
	if v, ok := dir["object-src"]; !ok || !strings.Contains(v, "'none'") {
		f = append(f, "object-src not 'none'")
	}
	if v, ok := dir["base-uri"]; !ok || !strings.Contains(v, "'none'") {
		f = append(f, "base-uri not 'none'")
	}
	if _, ok := dir["frame-ancestors"]; !ok {
		f = append(f, "missing frame-ancestors")
	}
	if v, ok := dir["script-src"]; ok {
		l := strings.ToLower(v)
		if strings.Contains(l, "'unsafe-inline'") &&
			!strings.Contains(l, "nonce-") &&
			!strings.Contains(l, "sha256-") &&
			!strings.Contains(l, "sha384-") &&
			!strings.Contains(l, "sha512-") {
			f = append(f, "script-src allows 'unsafe-inline' without nonces or hashes")
		}
		if strings.Contains(l, "*") {
			f = append(f, "script-src uses wildcard '*'")
		}
	}
	return f
}

func tokenizeCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		out = append(out, strings.ToLower(p))
	}
	return out
}

func containsStr(sl []string, v string) bool {
	for _, s := range sl {
		if s == v {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func cspDirective(csp, name string) string {
	// returns value of 'name' directive (first token after)
	name = strings.ToLower(name)
	for _, p := range strings.Split(csp, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ws := strings.Fields(p)
		if len(ws) >= 2 && strings.ToLower(ws[0]) == name {
			return strings.Trim(ws[1], " '\"")
		}
	}
	return ""
}

func parseReportingEndpoints(v string) map[string]string {
	// spec format: group="https://example.com/reports", other="https://.."
	out := map[string]string{}
	// split by commas at top-level (naive but ok for typical cases)
	parts := splitCommaTopLevel(v)
	re := regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=\s*"(https://[^"]+)"\s*$`)
	for _, p := range parts {
		m := re.FindStringSubmatch(p)
		if len(m) == 3 {
			out[m[1]] = m[2]
		}
	}
	return out
}

func splitCommaTopLevel(s string) []string {
	var parts []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch r {
		case '"':
			quoted = !quoted
			cur.WriteRune(r)
		case ',':
			if quoted {
				cur.WriteRune(r)
			} else {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

func summarize(checks []Check) Summary {
	var s Summary
	for _, c := range checks {
		switch c.Status {
		case PASS:
			s.Pass++
		case WARN:
			s.Warn++
		case FAIL:
			s.Fail++
		case INFO:
			s.Info++
		}
	}
	return s
}

func mergeHTTPProbe(primary *Report, httpProbe *Report) {
	// add a specific check about explicit HTTP origin behavior
	for _, c := range httpProbe.Checks {
		if c.Item == "HTTP→HTTPS Redirect" {
			primary.Checks = append(primary.Checks, Check{
				Item:   "HTTP Origin Probe",
				Status: c.Status,
				Msg:    c.Msg + " (explicit http://" + httpProbe.FinalURL + ")",
			})
			break
		}
	}
}

func newClientWithHistory() (*http.Client, *[]string) {
	h := &[]string{}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow silently, history captured by transport
		},
	}
	base := http.DefaultTransport
	client.Transport = &historyTransport{rt: base, history: h}
	return client, h
}

type historyTransport struct {
	rt      http.RoundTripper
	history *[]string
}

func (t *historyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.history != nil {
		*t.history = append(*t.history, r.URL.String())
	}
	return t.rt.RoundTrip(r)
}

// ----------- pretty output -----------

func printPretty(rep Report) {
	title := fmt.Sprintf("== %s ==", rep.Target)
	fmt.Println(bold(title))
	if rep.FinalURL != "" && rep.FinalURL != rep.Target {
		fmt.Printf("%s Final URL: %s\n", dim("i"), rep.FinalURL)
	}
	// table
	rows := [][]string{{"Status", "Check", "Details"}}
	for _, c := range rep.Checks {
		rows = append(rows, []string{colorStatus(c.Status), c.Item, c.Msg})
	}
	printTable(rows)
	fmt.Printf("\nSummary: %s %d  %s %d  %s %d  %s %d\n",
		green("PASS"), rep.Summary.Pass,
		yellow("WARN"), rep.Summary.Warn,
		red("FAIL"), rep.Summary.Fail,
		blue("INFO"), rep.Summary.Info,
	)
}

func colorStatus(s string) string {
	switch s {
	case PASS:
		return green("✔ PASS")
	case WARN:
		return yellow("▲ WARN")
	case FAIL:
		return red("✘ FAIL")
	default:
		return blue("ℹ INFO")
	}
}

func printTable(rows [][]string) {
	// compute widths
	w := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if l := visibleLen(stripANSI(c)); l > w[i] {
				w[i] = l
			}
		}
	}
	// print with padding
	for i, r := range rows {
		for j, c := range r {
			pad := w[j] - visibleLen(stripANSI(c))
			if j == len(r)-1 {
				fmt.Printf("%s\n", c)
			} else {
				if i == 0 {
					fmt.Printf("%s%s  ", bold(c), strings.Repeat(" ", pad))
				} else {
					fmt.Printf("%s%s  ", c, strings.Repeat(" ", pad))
				}
			}
		}
	}
}

// ANSI helpers
func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func blue(s string) string   { return "\033[34m" + s + "\033[0m" }
func dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }
func visibleLen(s string) int   { return len([]rune(s)) }

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out, sc.Err()
}

func jsonOut(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func exitByCI(rep Report) {
	os.Exit(ciExitCode(rep))
}

func ciExitCode(rep Report) int {
	switch strings.ToLower(*ciLevel) {
	case "fail":
		if rep.Summary.Fail > 0 {
			return 2
		}
	case "warn":
		if rep.Summary.Fail > 0 || rep.Summary.Warn > 0 {
			return 1
		}
	}
	return 0
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func fatal(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "fatal: "+f+"\n", a...)
	os.Exit(2)
}
