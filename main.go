// Command adguard-exporter exposes AdGuard Home statistics as Prometheus metrics.
//
// It has no dependencies outside the Go standard library: each scrape of /metrics queries
// /control/status and /control/stats of every configured AdGuard Home instance and renders
// the Prometheus text format directly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type target struct {
	URL      string
	Username string
	Password string
}

type status struct {
	Running           bool   `json:"running"`
	ProtectionEnabled bool   `json:"protection_enabled"`
	Version           string `json:"version"`
}

type stats struct {
	NumDNSQueries           float64              `json:"num_dns_queries"`
	NumBlockedFiltering     float64              `json:"num_blocked_filtering"`
	NumReplacedSafebrowsing float64              `json:"num_replaced_safebrowsing"`
	NumReplacedSafesearch   float64              `json:"num_replaced_safesearch"`
	NumReplacedParental     float64              `json:"num_replaced_parental"`
	AvgProcessingTime       float64              `json:"avg_processing_time"`
	TopClients              []map[string]float64 `json:"top_clients"`
	TopQueriedDomains       []map[string]float64 `json:"top_queried_domains"`
	TopBlockedDomains       []map[string]float64 `json:"top_blocked_domains"`
	TopUpstreamsResponses   []map[string]float64 `json:"top_upstreams_responses"`
	TopUpstreamsAvgTime     []map[string]float64 `json:"top_upstreams_avg_time"`
}

type result struct {
	target target
	status status
	stats  stats
	err    error
}

// parseTargets reads the comma-separated ADGUARD_SERVERS/USERNAMES/PASSWORDS lists.
// A single username or password applies to every server.
func parseTargets(servers, usernames, passwords string) ([]target, error) {
	urls := splitList(servers)
	if len(urls) == 0 {
		return nil, errors.New("ADGUARD_SERVERS is empty")
	}
	users, pass := splitList(usernames), splitList(passwords)
	pick := func(list []string, i int, name string) (string, error) {
		switch len(list) {
		case 0:
			return "", nil
		case 1:
			return list[0], nil
		case len(urls):
			return list[i], nil
		}
		return "", fmt.Errorf("%s has %d entries for %d servers", name, len(list), len(urls))
	}
	targets := make([]target, len(urls))
	for i, u := range urls {
		user, err := pick(users, i, "ADGUARD_USERNAMES")
		if err != nil {
			return nil, err
		}
		pw, err := pick(pass, i, "ADGUARD_PASSWORDS")
		if err != nil {
			return nil, err
		}
		targets[i] = target{URL: strings.TrimRight(u, "/"), Username: user, Password: pw}
	}
	return targets, nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func getJSON(ctx context.Context, client *http.Client, t target, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL+path, nil)
	if err != nil {
		return err
	}
	if t.Username != "" || t.Password != "" {
		req.SetBasicAuth(t.Username, t.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	// AdGuard's responses are small; cap them so a misbehaving server cannot exhaust memory
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

func collect(ctx context.Context, client *http.Client, targets []target) []result {
	results := make([]result, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := result{target: t}
			if r.err = getJSON(ctx, client, t, "/control/status", &r.status); r.err == nil {
				r.err = getJSON(ctx, client, t, "/control/stats", &r.stats)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	return results
}

type sample struct {
	labels [][2]string
	value  float64
}

type family struct {
	name, help, kind string
	samples          []sample
}

func (f *family) add(value float64, labels ...string) {
	s := sample{value: value}
	for i := 0; i+1 < len(labels); i += 2 {
		s.labels = append(s.labels, [2]string{labels[i], labels[i+1]})
	}
	f.samples = append(f.samples, s)
}

// topList adds one sample per entry of an AdGuard "top" list ([{"key": count}, ...]).
func (f *family) topList(server, label string, list []map[string]float64) {
	for _, entry := range list {
		for k, v := range entry {
			f.add(v, "server", server, label, k)
		}
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// render writes the metrics in the Prometheus text exposition format. Metric names match
// those of henrywhitaker3/adguard-exporter so existing dashboards keep working.
func render(w io.Writer, results []result) {
	fam := func(name, kind, help string) *family { return &family{name: name, kind: kind, help: help} }
	up := fam("adguard_up", "gauge", "Whether the last scrape of the AdGuard Home instance succeeded")
	running := fam("adguard_running", "gauge", "Whether AdGuard Home reports its DNS server as running")
	protection := fam("adguard_protection_enabled", "gauge", "Whether DNS filtering is enabled")
	info := fam("adguard_info", "gauge", "AdGuard Home version")
	queries := fam("adguard_queries", "gauge", "Total queries processed in the stats window")
	blocked := fam("adguard_queries_blocked", "gauge", "Queries blocked by filter lists in the stats window")
	safebrowsing := fam("adguard_replaced_safebrowsing", "gauge", "Queries replaced due to safe browsing in the stats window")
	safesearch := fam("adguard_replaced_safesearch", "gauge", "Queries replaced due to safe search in the stats window")
	parental := fam("adguard_replaced_parental", "gauge", "Queries replaced due to parental control in the stats window")
	avgTime := fam("adguard_avg_processing_time_seconds", "gauge", "Average query processing time in seconds")
	topClients := fam("adguard_top_clients", "gauge", "Queries of the top clients in the stats window")
	topQueried := fam("adguard_top_queried_domains", "gauge", "Queries of the top queried domains in the stats window")
	topBlocked := fam("adguard_top_blocked_domains", "gauge", "Blocked queries of the top blocked domains in the stats window")
	topUpstreams := fam("adguard_top_upstreams", "gauge", "Responses of the top upstream servers in the stats window")
	upstreamTime := fam("adguard_top_upstreams_avg_response_time_seconds", "gauge", "Average response time of the top upstream servers in seconds")

	for _, r := range results {
		s := r.target.URL
		if r.err != nil {
			up.add(0, "server", s)
			continue
		}
		up.add(1, "server", s)
		running.add(boolValue(r.status.Running), "server", s)
		protection.add(boolValue(r.status.ProtectionEnabled), "server", s)
		info.add(1, "server", s, "version", r.status.Version)
		queries.add(r.stats.NumDNSQueries, "server", s)
		blocked.add(r.stats.NumBlockedFiltering, "server", s)
		safebrowsing.add(r.stats.NumReplacedSafebrowsing, "server", s)
		safesearch.add(r.stats.NumReplacedSafesearch, "server", s)
		parental.add(r.stats.NumReplacedParental, "server", s)
		avgTime.add(r.stats.AvgProcessingTime, "server", s)
		topClients.topList(s, "client", r.stats.TopClients)
		topQueried.topList(s, "domain", r.stats.TopQueriedDomains)
		topBlocked.topList(s, "domain", r.stats.TopBlockedDomains)
		topUpstreams.topList(s, "upstream", r.stats.TopUpstreamsResponses)
		upstreamTime.topList(s, "upstream", r.stats.TopUpstreamsAvgTime)
	}

	for _, f := range []*family{up, running, protection, info, queries, blocked, safebrowsing, safesearch,
		parental, avgTime, topClients, topQueried, topBlocked, topUpstreams, upstreamTime} {
		if len(f.samples) == 0 {
			continue
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		lines := make([]string, len(f.samples))
		for i, s := range f.samples {
			lines[i] = f.name + formatLabels(s.labels) + " " + strconv.FormatFloat(s.value, 'g', -1, 64)
		}
		sort.Strings(lines) // map iteration order is random; keep the output stable
		for _, l := range lines {
			fmt.Fprintln(w, l)
		}
	}
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func formatLabels(labels [][2]string) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = l[0] + `="` + labelEscaper.Replace(l[1]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	targets, err := parseTargets(os.Getenv("ADGUARD_SERVERS"), os.Getenv("ADGUARD_USERNAMES"), os.Getenv("ADGUARD_PASSWORDS"))
	if err != nil {
		log.Fatal(err)
	}
	timeout, err := time.ParseDuration(env("SCRAPE_TIMEOUT", "10s"))
	if err != nil {
		log.Fatalf("SCRAPE_TIMEOUT: %v", err)
	}
	listen := env("LISTEN_ADDR", ":9618")
	client := &http.Client{Timeout: timeout}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		results := collect(ctx, client, targets)
		for _, res := range results {
			if res.err != nil {
				log.Printf("scrape %s: %v", res.target.URL, res.err)
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		render(w, results)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("listening on %s for %d AdGuard Home instance(s)", listen, len(targets))
	log.Fatal(srv.ListenAndServe())
}
