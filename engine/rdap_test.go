package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const rdapComDomain = `{
  "objectClassName": "domain",
  "ldhName": "EXAMPLE.COM",
  "status": ["client delete prohibited", "Client Transfer Prohibited"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43Z"},
    {"eventAction": "last update of RDAP database", "eventDate": "2026-11-04T16:37:19Z"}
  ],
  "nameservers": [{"ldhName": "ELLIOTT.NS.EXAMPLE.NET"}, {"ldhName": "hera.ns.example.net"}],
  "secureDNS": {"delegationSigned": true},
  "entities": [
    {"roles": ["registrant"], "vcardArray": ["vcard", [
      ["version", {}, "text", "4.0"],
      ["fn", {}, "text", "FAKE-REGISTRANT-NAME"],
      ["email", {}, "text", "fake-registrant@example.org"],
      ["tel", {}, "text", "+00 000 FAKE-PHONE"]]]},
    {"roles": ["registrar"], "vcardArray": ["vcard", [
      ["version", {}, "text", "4.0"],
      ["fn", {}, "text", "Example Registrar Inc."]]],
     "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]}
  ]
}`

// rdapTestServer serves an IANA-style bootstrap and domain lookups over TLS and
// points the engine at it. bootstrapHits counts fetches of the bootstrap file.
type rdapFake struct {
	srv           *httptest.Server
	bootstrapHits atomic.Int32
	lastReq       atomic.Pointer[http.Request]
}

func newRdapFake(t *testing.T, domainHandlers map[string]http.HandlerFunc) *rdapFake {
	t.Helper()
	f := &rdapFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, _ *http.Request) {
		f.bootstrapHits.Add(1)
		base := f.srv.URL
		// "http://" first, to prove the https server is preferred.
		w.Write([]byte(`{"services": [
			[["com"], ["http://127.0.0.1:1/com/", "` + base + `/com/"]],
			[["uk"], ["` + base + `/uk/"]]
		]}`))
	})
	for path, h := range domainHandlers {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			f.lastReq.Store(r)
			h(w, r)
		})
	}
	f.srv = httptest.NewTLSServer(mux)

	origURL, origClient := rdapBootstrapURL, rdapHTTP
	rdapBootstrapURL, rdapHTTP = f.srv.URL+"/dns.json", f.srv.Client()
	resetRdapBootstrap()
	t.Cleanup(func() {
		f.srv.Close()
		rdapBootstrapURL, rdapHTTP = origURL, origClient
		resetRdapBootstrap()
	})
	return f
}

func serve(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }
}

func TestRunRdap_ParsesRegistration(t *testing.T) {
	newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(rdapComDomain)})
	r, err := RunRdap(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "example.com" || r.Registrar != "Example Registrar Inc." {
		t.Errorf("domain/registrar = %q / %q", r.Domain, r.Registrar)
	}
	if r.Registered != "1995-08-14T04:00:00Z" || r.Expires != "2027-08-13T04:00:00Z" || r.LastChanged != "2026-08-14T08:01:43Z" {
		t.Errorf("dates = %q %q %q", r.Registered, r.Expires, r.LastChanged)
	}
	if strings.Join(r.Status, ",") != "client delete prohibited,client transfer prohibited" {
		t.Errorf("status = %v, want lowercased", r.Status)
	}
	if strings.Join(r.Nameservers, ",") != "elliott.ns.example.net,hera.ns.example.net" {
		t.Errorf("nameservers = %v, want lowercased", r.Nameservers)
	}
	if !r.DNSSEC {
		t.Error("dnssec = false, want true")
	}
}

func TestRunRdap_NeverReadsContactDetails(t *testing.T) {
	newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(rdapComDomain)})
	r, err := RunRdap(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	for _, secret := range []string{"FAKE-REGISTRANT-NAME", "fake-registrant@example.org", "FAKE-PHONE"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("result contains registrant contact data %q", secret)
		}
	}
}

func TestRunRdap_RegistrarFallsBackToPublicID(t *testing.T) {
	newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(`{
		"entities": [{"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]}]}`)})
	r, err := RunRdap(context.Background(), "example.com")
	if err != nil || r.Registrar != "IANA Registrar ID 376" {
		t.Errorf("registrar = %q, err = %v", r.Registrar, err)
	}
}

func TestRunRdap_LooksUpTheRegistrableDomainAtTheRegistry(t *testing.T) {
	f := newRdapFake(t, map[string]http.HandlerFunc{
		"/com/domain/example.com":  serve(rdapComDomain),
		"/uk/domain/example.co.uk": serve(`{"status": ["active"]}`),
	})
	if _, err := RunRdap(context.Background(), "www.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := f.lastReq.Load().URL.Path; got != "/com/domain/example.com" {
		t.Errorf("path = %q, want the registrable domain example.com", got)
	}
	// A two-part suffix is looked up at the registry of its last label.
	r, err := RunRdap(context.Background(), "shop.example.co.uk")
	if err != nil || r.Domain != "example.co.uk" {
		t.Fatalf("co.uk: domain = %v err = %v", r, err)
	}
	if got := f.lastReq.Load().URL.Path; got != "/uk/domain/example.co.uk" {
		t.Errorf("path = %q", got)
	}
}

func TestRunRdap_PrefersHttpsAndIdentifiesItself(t *testing.T) {
	f := newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(rdapComDomain)})
	r, err := RunRdap(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Server, "https://") {
		t.Errorf("server = %q, want the https one", r.Server)
	}
	req := f.lastReq.Load()
	if !strings.HasPrefix(req.Header.Get("User-Agent"), "hopper-recon/") {
		t.Errorf("User-Agent = %q", req.Header.Get("User-Agent"))
	}
	if !strings.Contains(req.Header.Get("Accept"), "application/rdap+json") {
		t.Errorf("Accept = %q", req.Header.Get("Accept"))
	}
}

func TestRunRdap_BootstrapIsCachedThenRefetched(t *testing.T) {
	f := newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(rdapComDomain)})
	for range 3 {
		if _, err := RunRdap(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.bootstrapHits.Load(); n != 1 {
		t.Errorf("bootstrap fetched %d times for 3 lookups, want 1", n)
	}
	rdapBootstrap.mu.Lock()
	rdapBootstrap.fetched = time.Now().Add(-rdapBootstrapTTL - time.Minute)
	rdapBootstrap.mu.Unlock()
	if _, err := RunRdap(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if n := f.bootstrapHits.Load(); n != 2 {
		t.Errorf("bootstrap fetched %d times after the TTL, want 2", n)
	}
}

func TestRunRdap_Errors(t *testing.T) {
	cases := []struct {
		name    string
		domain  string
		routes  map[string]http.HandlerFunc
		wantErr string
	}{
		{"not found", "example.com", map[string]http.HandlerFunc{
			"/com/domain/example.com": func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) }},
			"not in the .com registry"},
		{"server error", "example.com", map[string]http.HandlerFunc{
			"/com/domain/example.com": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }},
			"HTTP 500"},
		{"unreadable body", "example.com", map[string]http.HandlerFunc{
			"/com/domain/example.com": serve("<html>not json</html>")},
			"unreadable RDAP response"},
		{"tld without RDAP", "example.xyz", nil, "no RDAP service is registered for .xyz"},
		{"not a domain", "localhost", nil, "expected a domain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			newRdapFake(t, c.routes)
			_, err := RunRdap(context.Background(), c.domain)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

func TestRunRdap_BootstrapFailureIsAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	origURL, origClient := rdapBootstrapURL, rdapHTTP
	rdapBootstrapURL, rdapHTTP = srv.URL+"/dns.json", srv.Client()
	resetRdapBootstrap()
	t.Cleanup(func() { rdapBootstrapURL, rdapHTTP = origURL, origClient; resetRdapBootstrap() })
	if _, err := RunRdap(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "bootstrap returned HTTP 503") {
		t.Errorf("err = %v, want the bootstrap status", err)
	}
}

func TestRunTool_LookupRdap(t *testing.T) {
	newRdapFake(t, map[string]http.HandlerFunc{"/com/domain/example.com": serve(rdapComDomain)})
	out, err := runTool(context.Background(), "lookup_rdap", "example.com")
	if err != nil || len(out) != 1 {
		t.Fatalf("out = %v err = %v", out, err)
	}
	if r, ok := out[0].(*RdapResult); !ok || r.Registrar != "Example Registrar Inc." {
		t.Errorf("result = %#v", out[0])
	}
}
