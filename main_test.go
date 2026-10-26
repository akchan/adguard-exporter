package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	ts, err := parseTargets("http://a/, http://b", "admin", "p1,p2")
	if err != nil {
		t.Fatal(err)
	}
	want := []target{{"http://a", "admin", "p1"}, {"http://b", "admin", "p2"}}
	for i := range want {
		if ts[i] != want[i] {
			t.Errorf("target %d = %+v, want %+v", i, ts[i], want[i])
		}
	}
	if _, err := parseTargets("http://a,http://b,http://c", "u", "p1,p2"); err == nil {
		t.Error("mismatched password count should fail")
	}
	if _, err := parseTargets(" ", "", ""); err == nil {
		t.Error("empty server list should fail")
	}
}

func TestScrapeAndRender(t *testing.T) {
	adguard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "admin" || p != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/control/status":
			w.Write([]byte(`{"version":"v0.107.79","protection_enabled":true,"running":true}`))
		case "/control/stats":
			w.Write([]byte(`{"num_dns_queries":1477487,"num_blocked_filtering":12,"num_replaced_safebrowsing":7,
				"num_replaced_safesearch":0,"num_replaced_parental":1,"avg_processing_time":0.025307,
				"top_clients":[{"192.168.131.200":160083}],"top_queried_domains":[{"yahoo.co.jp":82815}],
				"top_blocked_domains":[],"top_upstreams_responses":[{"[2001:db8::a]:53":290787}],
				"top_upstreams_avg_time":[{"1.1.1.1:53":0.0288}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer adguard.Close()

	targets := []target{{adguard.URL, "admin", "secret"}, {adguard.URL + "/x", "admin", "wrong"}}
	var out strings.Builder
	render(&out, collect(context.Background(), adguard.Client(), targets))
	got := out.String()

	s := adguard.URL
	for _, line := range []string{
		`adguard_up{server="` + s + `"} 1`,
		`adguard_up{server="` + s + `/x"} 0`,
		`adguard_protection_enabled{server="` + s + `"} 1`,
		`adguard_info{server="` + s + `",version="v0.107.79"} 1`,
		`adguard_queries{server="` + s + `"} 1.477487e+06`,
		`adguard_queries_blocked{server="` + s + `"} 12`,
		`adguard_replaced_safebrowsing{server="` + s + `"} 7`,
		`adguard_replaced_parental{server="` + s + `"} 1`,
		`adguard_avg_processing_time_seconds{server="` + s + `"} 0.025307`,
		`adguard_top_clients{server="` + s + `",client="192.168.131.200"} 160083`,
		`adguard_top_queried_domains{server="` + s + `",domain="yahoo.co.jp"} 82815`,
		`adguard_top_upstreams{server="` + s + `",upstream="[2001:db8::a]:53"} 290787`,
		"# TYPE adguard_queries gauge",
	} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in output:\n%s", line, got)
		}
	}
	if strings.Contains(got, "adguard_top_blocked_domains") {
		t.Error("empty families should be omitted")
	}
	if strings.Contains(got, `adguard_queries{server="`+s+`/x"}`) {
		t.Error("failed targets should only report adguard_up")
	}
}

func TestFormatLabelsEscapes(t *testing.T) {
	got := formatLabels([][2]string{{"domain", "a\"b\\c\nd"}})
	if want := `{domain="a\"b\\c\nd"}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
