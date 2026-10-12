package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestInstanceLockPreventsSecondInstance(t *testing.T) {
	if runtime.GOOS != "windows" || testing.Short() {
		t.Skip("uses a Windows named mutex")
	}
	name := "Local\\YZUAutoLogin-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	release, err := acquireInstanceLockNamed(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)

	secondRelease, err := acquireInstanceLockNamed(name)
	if secondRelease != nil {
		secondRelease()
		t.Fatal("second instance unexpectedly acquired the lock")
	}
	if !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("expected already-running error, got %v", err)
	}
}

func TestWebUIRefreshDoesNotOverwriteConfigForm(t *testing.T) {
	if strings.Contains(indexHTML, "setInterval(load,5000)") {
		t.Fatal("periodic refresh overwrites form fields while the user is typing")
	}
	if !strings.Contains(indexHTML, "setInterval(loadStatus,5000)") {
		t.Fatal("status is no longer refreshed periodically")
	}
}

func TestWebUIExposesTheServiceSelector(t *testing.T) {
	// The dropdown, the value it loads, and the value it submits must stay wired
	// together; dropping any of the three silently pins every login back to the
	// default service.
	for _, want := range []string{`<select id="service">`, `'username','service',`, `service:$('service').value`} {
		if !strings.Contains(indexHTML, want) {
			t.Fatalf("the service selector is no longer wired into the WebUI: missing %q", want)
		}
	}
	if !strings.Contains(indexHTML, "c.services") {
		t.Fatal("the dropdown no longer renders the service list served by /api/config")
	}
}

func TestConfigPasswordUsesLocalEncryptionKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	err = store.update(configUpdate{
		Username:        "student-id",
		Password:        "not-plaintext",
		ProbeURL:        "https://example.test/probe",
		PortalHost:      "sso.yzu.edu.cn",
		IntervalSeconds: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	username, password, err := store.credentials()
	if err != nil {
		t.Fatal(err)
	}
	if username != "student-id" || password != "not-plaintext" {
		t.Fatalf("unexpected credentials: %q, %q", username, password)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "not-plaintext") {
		t.Fatal("password was written to config as plaintext")
	}
	key, err := os.ReadFile(filepath.Join(filepath.Dir(path), "secret.key"))
	if err != nil {
		t.Fatalf("secret key was not created: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("unexpected key size: %d", len(key))
	}
}

func TestLegacyDPAPIFieldIsRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"version":1,"username":"student-id","password_dpapi":"legacy","probe_url":"https://example.test/probe","portal_host":"sso.yzu.edu.cn","interval_seconds":60,"web_port":8765}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := newConfigStore(path); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "password_dpapi") {
		t.Fatal("legacy DPAPI field was not removed")
	}
}

func TestNormalizeServiceFallsBackToDefault(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"a blank value keeps the telecom behaviour of earlier builds", "", defaultPortalService},
		{"a padded value is trimmed", "  移动互联网服务  ", "移动互联网服务"},
		{"a known value survives unchanged", "联通互联网服务", "联通互联网服务"},
		{"an unknown value falls back instead of failing every login", "并不存在的服务", defaultPortalService},
	}
	for _, testCase := range cases {
		if got := normalizeService(testCase.input); got != testCase.want {
			t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func TestConfigWithoutServiceMigratesToDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"version":1,"username":"student-id","probe_url":"https://example.test/probe","portal_host":"sso.yzu.edu.cn","interval_seconds":60,"web_port":8765}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.snapshot().Service; got != defaultPortalService {
		t.Fatalf("legacy config resolved to %q, want %q", got, defaultPortalService)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"service": "`+defaultPortalService+`"`) {
		t.Fatalf("normalized service was not persisted: %s", contents)
	}
}

func TestConfigUpdateStoresTheSelectedService(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := newConfigStore(path)
	if err != nil {
		t.Fatal(err)
	}
	update := configUpdate{
		Username: "student-id", Password: "secret", Service: "联通互联网服务",
		ProbeURL: "https://example.test/probe", PortalHost: "sso.yzu.edu.cn",
		ProbeExpectedText: "ok", IntervalSeconds: 60,
	}
	if err := store.update(update); err != nil {
		t.Fatal(err)
	}
	if got := store.snapshot().Service; got != "联通互联网服务" {
		t.Fatalf("selected service was not stored: %q", got)
	}
	// A selection the portal does not offer must not leave the config in a state
	// where every later login fails.
	update.Service = "并不存在的服务"
	if err := store.update(update); err != nil {
		t.Fatal(err)
	}
	if got := store.snapshot().Service; got != defaultPortalService {
		t.Fatalf("unknown service resolved to %q, want %q", got, defaultPortalService)
	}
}

func TestSelectedPortalServiceReachesCookiesAndLogin(t *testing.T) {
	const selected = "移动互联网服务"
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("method") != "loginOfCas" {
			t.Fatalf("unexpected method: %s", r.URL.RawQuery)
		}
		cookie, err := r.Cookie("EPORTAL_COOKIE_SERVER")
		if err != nil || cookie.Value != url.QueryEscape(selected) {
			t.Fatalf("cookie carried the wrong service: %v %v", cookie, err)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.PostForm.Get("service") != url.QueryEscape(selected) {
			t.Fatalf("form carried the wrong service: %q", r.PostForm.Get("service"))
		}
		_, _ = w.Write([]byte(`{"result":"success"}`))
	}))
	defer server.Close()
	portalPage, err := url.Parse(server.URL + "/eportal/index.jsp?wlanuserip=1&mac=2")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	seedPortalServiceCookies(client, portalPage, selected)
	if err := submitPortalService(context.Background(), client, portalPage, "student-id", selected); err != nil {
		t.Fatal(err)
	}
}

func TestProbeDetectsPortalRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://sso.yzu.edu.cn/login?service=test")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	result, err := probe(context.Background(), Config{ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn"})
	if err != nil {
		t.Fatal(err)
	}
	if result.portalURL == "" || !result.redirect || !result.captive {
		t.Fatalf("portal redirect not detected: %#v", result)
	}
}

func TestProbeDetectsEportalGatewayRedirect(t *testing.T) {
	gateway := httptest.NewServer(http.NotFoundHandler())
	defer gateway.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", gateway.URL+"/eportal/index.jsp?wlanuserip=test&mac=test")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	result, err := probe(context.Background(), Config{ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedText: "Microsoft Connect Test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.portalURL != gateway.URL+"/eportal/index.jsp?wlanuserip=test&mac=test" || !result.redirect || !result.captive {
		t.Fatalf("eportal gateway redirect not detected: %#v", result)
	}
}

func TestProbeTreatsNormalResponseAsOnline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Microsoft Connect Test"))
	}))
	defer server.Close()

	result, err := probe(context.Background(), Config{ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedText: "Microsoft Connect Test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.portalURL != "" || result.captive {
		t.Fatalf("normal response incorrectly detected as portal: %#v", result)
	}
}

func TestProbeDetectsUnexpectedProbeBodyAsPortal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><script>location.href="https://sso.yzu.edu.cn/login?service=test"</script></html>`))
	}))
	defer server.Close()

	result, err := probe(context.Background(), Config{ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedText: "Microsoft Connect Test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.portalURL != "https://sso.yzu.edu.cn/login?service=test" || !result.captive {
		t.Fatalf("unexpected detected portal URL: %q", result.portalURL)
	}
}

func TestProbePreservesGatewayRedirect(t *testing.T) {
	var gateway *httptest.Server
	gateway = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gatewayURL, err := url.Parse(gateway.URL)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Location", (&url.URL{Scheme: "http", Host: "localhost:" + gatewayURL.Port(), Path: "/eportal/index.jsp", RawQuery: "wlanuserip=test"}).String())
		w.WriteHeader(http.StatusFound)
	}))
	defer gateway.Close()
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", gateway.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer entry.Close()

	result, err := probe(context.Background(), Config{ProbeURL: entry.URL, PortalHost: "localhost", ProbeExpectedText: "Microsoft Connect Test"})
	if err != nil {
		t.Fatal(err)
	}
	gatewayURL, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	expectedPortalURL := (&url.URL{Scheme: "http", Host: "localhost:" + gatewayURL.Port(), Path: "/eportal/index.jsp", RawQuery: "wlanuserip=test"}).String()
	if result.portalURL != expectedPortalURL || !result.captive {
		t.Fatalf("unexpected gateway URL: %q", result.portalURL)
	}
}

func TestProbeDoesNotUseProbeURLAsPortalURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("unexpected captive response"))
	}))
	defer server.Close()

	result, err := probe(context.Background(), Config{ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedText: "Microsoft Connect Test"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.captive || result.portalURL != "" {
		t.Fatalf("probe URL was incorrectly treated as portal: %#v", result)
	}
}

func TestFindSSOLoginURL(t *testing.T) {
	got := findSSOLoginURL(`window.location='https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.0.0.1&amp;foo=bar'`)
	if got != "https://sso.yzu.edu.cn/login?service=http%3A%2F%2F10.0.0.1&foo=bar" {
		t.Fatalf("unexpected SSO URL: %q", got)
	}
}

func TestFindPortalEntryURL(t *testing.T) {
	got := findPortalEntryURL(`<script>location.href="http:\/\/10.245.2.20\/eportal\/index.jsp?wlanuserip=test&amp;mac=test"</script>`)
	want := "http://10.245.2.20/eportal/index.jsp?wlanuserip=test&mac=test"
	if got != want {
		t.Fatalf("unexpected portal entry URL: %q", got)
	}
}

func TestAppLoggerRetainsRecentEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	logger, err := newLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.Printf("first event: %d", 1)
	logger.Printf("second event")
	entries := logger.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 log entries, got %d", len(entries))
	}
	if entries[0].Message != "first event: 1" || entries[1].Message != "second event" {
		t.Fatalf("unexpected log entries: %#v", entries)
	}
	if entries[0].Timestamp.IsZero() {
		t.Fatal("log timestamp was not set")
	}
}

func TestLogsAPI(t *testing.T) {
	logger, err := newLogger(filepath.Join(t.TempDir(), "app.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	logger.Printf("visible in WebUI")
	app := &App{logger: logger}
	recorder := httptest.NewRecorder()
	app.handleLogs(recorder, httptest.NewRequest(http.MethodGet, "/api/logs", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	var response struct {
		Entries []LogEntry `json:"entries"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) != 1 || response.Entries[0].Message != "visible in WebUI" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestParseSSOPage(t *testing.T) {
	page := pageValues(`<p id="current-login-type">UsernamePassword</p><p id="login-croypto">MDEyMzQ1Njc4OWFiY2RlZg==</p><p id="login-page-flowkey">flow-key</p>`)
	if page["current-login-type"] != "UsernamePassword" || page["login-page-flowkey"] != "flow-key" {
		t.Fatalf("unexpected parsed values: %#v", page)
	}
}

func TestAESECBEncryptUsesPKCS7(t *testing.T) {
	key := []byte("0123456789abcdef")
	encrypted, err := aesECBEncrypt(key, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != aes.BlockSize {
		t.Fatalf("expected one AES block, got %d bytes", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(ciphertext))
	block.Decrypt(plain, ciphertext)
	if string(plain[:5]) != "hello" {
		t.Fatalf("unexpected plaintext: %q", plain)
	}
	for _, b := range plain[5:] {
		if b != 11 {
			t.Fatalf("invalid PKCS7 padding: %v", plain)
		}
	}
}

func TestSubmitPortalService(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("method") != "loginOfCas" {
			t.Fatalf("unexpected method: %s", r.URL.RawQuery)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		// ParseForm removes the outer application/x-www-form-urlencoded layer.
		// The one remaining escaped layer matches the browser HAR; two remaining
		// layers would make the portal reject the request as an unknown device.
		if r.PostForm.Get("userId") != url.QueryEscape("student@example") {
			t.Fatalf("unexpected user ID value: %q", r.PostForm.Get("userId"))
		}
		if r.PostForm.Get("service") != url.QueryEscape(defaultPortalService) {
			t.Fatalf("unexpected service value: %q", r.PostForm.Get("service"))
		}
		if r.PostForm.Get("queryString") != url.QueryEscape("wlanuserip=1&mac=2") {
			t.Fatalf("unexpected query string value: %q", r.PostForm.Get("queryString"))
		}
		_, _ = w.Write([]byte(`{"result":"success"}`))
	}))
	defer server.Close()
	portalPage, err := url.Parse(server.URL + "/eportal/index.jsp?wlanuserip=1&mac=2")
	if err != nil {
		t.Fatal(err)
	}
	if err := submitPortalService(context.Background(), server.Client(), portalPage, "student@example", defaultPortalService); err != nil {
		t.Fatal(err)
	}
}

func TestInitializePortalServiceMatchesBrowserSequence(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/eportal/InterFace.do" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL)
		}
		switch r.URL.Query().Get("method") {
		case "pageInfo":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.PostForm.Get("queryString") != "wlanuserip=1&mac=2" || r.URL.Query().Get("queryString") != "" {
				t.Fatalf("unexpected pageInfo query placement: form=%q url=%q", r.PostForm.Get("queryString"), r.URL.Query().Get("queryString"))
			}
			calls = append(calls, "pageInfo")
		case "getServices":
			if r.URL.Query().Get("queryString") != "wlanuserip=1&mac=2" {
				t.Fatalf("unexpected getServices query: %q", r.URL.Query().Get("queryString"))
			}
			calls = append(calls, "getServices")
		case "getOnlineUserInfo":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if _, ok := r.PostForm["userIndex"]; !ok || r.PostForm.Get("userIndex") != "" {
				t.Fatalf("unexpected getOnlineUserInfo form: %#v", r.PostForm)
			}
			calls = append(calls, "getOnlineUserInfo")
		default:
			t.Fatalf("unexpected portal method: %q", r.URL.Query().Get("method"))
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded; charset=UTF-8" {
			t.Fatalf("unexpected content type: %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	portalPage, err := url.Parse(server.URL + "/eportal/index.jsp?wlanuserip=1&mac=2")
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePortalService(context.Background(), server.Client(), portalPage); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "pageInfo,getServices,getOnlineUserInfo" {
		t.Fatalf("unexpected initialization order: %v", calls)
	}
}

func TestWaitForPortalReadyHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForPortalReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled wait, got %v", err)
	}
}

func TestSeedPortalServiceCookiesMatchesBrowserHAR(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	portalURL, err := url.Parse("http://10.245.2.20/eportal/index.jsp?wlanuserip=1")
	if err != nil {
		t.Fatal(err)
	}
	seedPortalServiceCookies(client, portalURL, defaultPortalService)
	cookies := client.Jar.Cookies(portalURL)
	values := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		values[cookie.Name] = cookie.Value
	}
	if values["EPORTAL_COOKIE_SERVER"] != url.QueryEscape(defaultPortalService) || values["EPORTAL_COOKIE_SERVER_NAME"] != url.QueryEscape(defaultPortalService) || values["EPORTAL_COOKIE_DOMAIN"] != "false" {
		t.Fatalf("unexpected portal service cookies: %#v", values)
	}
	if _, ok := values["EPORTAL_COOKIE_OPERATORPWD"]; !ok {
		t.Fatal("missing EPORTAL_COOKIE_OPERATORPWD")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"EPORTAL_COOKIE_OPERATORPWD", "EPORTAL_COOKIE_SERVER", "EPORTAL_COOKIE_SERVER_NAME", "EPORTAL_COOKIE_DOMAIN"} {
			if _, err := r.Cookie(name); err != nil {
				t.Fatalf("outgoing request missed %s: %v", name, err)
			}
		}
		if cookie, _ := r.Cookie("EPORTAL_COOKIE_SERVER"); cookie.Value != url.QueryEscape(defaultPortalService) {
			t.Fatalf("unexpected outgoing service cookie: %q", cookie.Value)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL + "/eportal/index.jsp?wlanuserip=1")
	if err != nil {
		t.Fatal(err)
	}
	client = &http.Client{Jar: jar}
	seedPortalServiceCookies(client, serverURL, defaultPortalService)
	if _, err := client.Get(server.URL + "/eportal/check"); err != nil {
		t.Fatal(err)
	}
}

func TestPortalSessionDiagnosticsDoesNotExposeCookieValues(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	portalURL, err := url.Parse("http://example.test/eportal/index.jsp;jsessionid=secret?wlanuserip=1")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	seedPortalServiceCookies(client, portalURL, defaultPortalService)
	jar.SetCookies(portalURL, []*http.Cookie{{Name: "JSESSIONID", Value: "secret", Path: "/eportal"}})
	diagnostics := portalSessionDiagnostics(client, portalURL)
	if diagnostics != "JSESSIONID=true，服务Cookie=4/4，页面含jsessionid=true" {
		t.Fatalf("unexpected diagnostics: %q", diagnostics)
	}
	if strings.Contains(diagnostics, "secret") {
		t.Fatal("diagnostics exposed a cookie value")
	}
}

func TestSubmitPortalServiceReportsPortalRejectionReason(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`{"result": "fail", "msg": "当前账号已有在线会话"}`))
	}))
	defer server.Close()
	portalPage, err := url.Parse(server.URL + "/eportal/index.jsp?wlanuserip=1&mac=2")
	if err != nil {
		t.Fatal(err)
	}
	err = submitPortalService(context.Background(), server.Client(), portalPage, "student-id", defaultPortalService)
	if err == nil || !strings.Contains(err.Error(), "当前账号已有在线会话") {
		t.Fatalf("unexpected rejection error: %v", err)
	}
}

// A portal can answer the probe with its own 200 page instead of an HTTP
// redirect. That used to look exactly like a healthy reply: with no expected
// body or status there was nothing left to compare against, so the machine
// reported "online" and never signed in.
func TestProbeTreatsUnexpectedStatusAsPortalInterception(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><script>location.href='/eportal/index.jsp'</script></body></html>`))
	}))
	defer server.Close()
	result, err := probe(context.Background(), Config{
		ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedStatus: http.StatusNotFound,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.captive {
		t.Fatalf("an interstitial 200 page was accepted as connectivity: %#v", result)
	}
	if result.portalURL != "" {
		t.Fatalf("unexpected portal address: %q", result.portalURL)
	}
}

func TestProbeAcceptsTheExpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("\n"))
	}))
	defer server.Close()
	result, err := probe(context.Background(), Config{
		ProbeURL: server.URL, PortalHost: "sso.yzu.edu.cn", ProbeExpectedStatus: http.StatusNotFound,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.captive {
		t.Fatalf("a matching status was still treated as interception: %#v", result)
	}
}

// Every built-in IP probe must ship an expected status. An IP literal has no
// fixed body to compare against, so without one any 200 page — including the
// portal's own — counts as proof of connectivity.
func TestBuiltInIPProbesExpectAStatus(t *testing.T) {
	if len(ipDirectProbes) == 0 {
		t.Fatal("no built-in IP probes")
	}
	for _, target := range ipDirectProbes {
		if target.expectedStatus == 0 {
			t.Errorf("%s has no expected status, so any reply would count as connectivity", target.url)
		}
		if !target.onlineWhenNormal {
			t.Errorf("%s cannot prove connectivity, so it does not belong in this list", target.url)
		}
	}
}

// useIPProbes swaps the package-level IP fallback list for one test. The list is
// a variable so a test can point it at an httptest server instead of the
// internet, which also keeps the suite offline. The stubs carry no expected
// status, so a test server may answer with whatever body it likes.
func useIPProbes(t *testing.T, urls ...string) {
	t.Helper()
	previous := ipDirectProbes
	probes := make([]probeTarget, 0, len(urls))
	for _, targetURL := range urls {
		probes = append(probes, probeTarget{url: targetURL, timeout: ipProbeTimeout, onlineWhenNormal: true})
	}
	ipDirectProbes = probes
	t.Cleanup(func() { ipDirectProbes = previous })
}

// unreachableURL returns a loopback address that refuses connections
// immediately. It reproduces "the configured probe cannot be reached" without
// depending on any particular port being free on the host.
func unreachableURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + address + "/"
}

func TestParseDefaultGateway(t *testing.T) {
	const english = `
===========================================================================
Interface List
 14...aa bb cc dd ee ff ......Intel(R) Ethernet Connection
===========================================================================
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.100    281
`
	gateway, ok := parseDefaultGateway(english)
	if !ok || gateway != "192.168.1.1" {
		t.Fatalf("unexpected gateway: %q ok=%t", gateway, ok)
	}

	// A localized Windows translates the headers and the "on-link" marker but
	// keeps the numeric columns, so the parser must depend on neither.
	const localized = `
活动路由:
网络目标        网络掩码         网关        接口     跃点数
          0.0.0.0          0.0.0.0     10.20.30.1    10.20.30.44     25
       10.20.30.0    255.255.255.0          在链路上    10.20.30.44    281
`
	gateway, ok = parseDefaultGateway(localized)
	if !ok || gateway != "10.20.30.1" {
		t.Fatalf("unexpected localized gateway: %q ok=%t", gateway, ok)
	}

	if gateway, ok := parseDefaultGateway("Active Routes:\nNetwork Destination  Netmask  Gateway  Interface  Metric\n"); ok {
		t.Fatalf("an empty routing table reported gateway %q", gateway)
	}
}

func TestParseDefaultGatewayPrefersLowestMetric(t *testing.T) {
	// Two adapters publish a default route; the higher metric one is a fallback.
	const table = `
          0.0.0.0          0.0.0.0     192.168.0.1    192.168.0.20     50
          0.0.0.0          0.0.0.0       10.0.0.1       10.0.0.20     10
`
	gateway, ok := parseDefaultGateway(table)
	if !ok || gateway != "10.0.0.1" {
		t.Fatalf("unexpected gateway: %q ok=%t", gateway, ok)
	}
}

func TestClassifyNetworkErrorSeparatesDNSFromLinkFailures(t *testing.T) {
	dnsFailure := &net.DNSError{Err: "no such host", Name: "www.msftconnecttest.com", IsNotFound: true}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns lookup", dnsFailure, "DNS 解析失败"},
		{"dns lookup wrapped by http", &url.Error{Op: "Get", URL: "http://probe.test/", Err: dnsFailure}, "DNS 解析失败"},
		{"dns timeout", &net.DNSError{Err: "timeout", IsTimeout: true}, "DNS 解析超时"},
		{"request deadline", context.DeadlineExceeded, "连接超时"},
		{"dial refused", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, "无法建立连接"},
		{"opaque", errors.New("boom"), "请求失败"},
	}
	for _, testCase := range cases {
		if got := classifyNetworkError(testCase.err); got != testCase.want {
			t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func TestDiscoveryFailureSummarySeparatesReasons(t *testing.T) {
	found := discovery{failures: []probeFailure{
		{kind: "DNS 解析失败", err: errors.New("lookup www.msftconnecttest.com: no such host")},
		{kind: "连接超时", err: errors.New("context deadline exceeded")},
		{kind: "DNS 解析失败", err: errors.New("lookup fallback.test: no such host")},
	}}
	if got := found.failureKinds(); got != "DNS 解析失败×2，连接超时×1" {
		t.Fatalf("unexpected status summary: %q", got)
	}
	if !found.hasDNSFailure() {
		t.Fatal("the DNS failure was not detected")
	}
	summary := found.failureSummary()
	if !strings.Contains(summary, "no such host") || !strings.Contains(summary, "连接超时") {
		t.Fatalf("the log summary lost its diagnostic detail: %q", summary)
	}
}

// The reported outage: the configured probe dies during name resolution, so the
// HTTP exchange that the portal would intercept never happens. An IP literal must
// take over and still surface the redirect.
func TestDiscoverFallsBackToIPProbeWhenConfiguredProbeIsUnreachable(t *testing.T) {
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://sso.yzu.edu.cn/login?service=test")
		w.WriteHeader(http.StatusFound)
	}))
	defer portal.Close()
	useIPProbes(t, portal.URL)

	cfg := Config{ProbeURL: unreachableURL(t), PortalHost: "sso.yzu.edu.cn", ProbeExpectedText: "Microsoft Connect Test"}
	found := discoverWithGateway(context.Background(), cfg, "", false)

	if found.online {
		t.Fatalf("an unreachable probe was reported as online: %#v", found)
	}
	if !found.captive || found.portalURL != "https://sso.yzu.edu.cn/login?service=test" {
		t.Fatalf("the portal was not discovered through the IP fallback: %#v", found)
	}
	if found.primaryFailureKind != "无法建立连接" {
		t.Fatalf("the configured probe failure was not recorded: %#v", found)
	}
	if len(found.failures) != 1 {
		t.Fatalf("expected exactly one recorded failure, got %#v", found.failures)
	}
}

func TestDiscoverReportsOnlineWhenOnlyIPProbeSucceeds(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("healthy"))
	}))
	defer healthy.Close()
	useIPProbes(t, healthy.URL)

	cfg := Config{ProbeURL: unreachableURL(t), PortalHost: "sso.yzu.edu.cn"}
	found := discoverWithGateway(context.Background(), cfg, "", false)

	if !found.online {
		t.Fatalf("a reachable IP probe should prove connectivity: %#v", found)
	}
	if found.primaryFailureKind == "" {
		t.Fatal("a broken resolver behind a healthy link must still be reported")
	}
}

// A router keeps answering with its own web interface while the uplink is dead,
// so a normal reply from the gateway must never be read as connectivity.
func TestDiscoverDoesNotTreatGatewayAdminPageAsOnline(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><title>Router Admin</title></html>"))
	}))
	defer gateway.Close()
	useIPProbes(t)

	address, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ProbeURL: unreachableURL(t), PortalHost: "sso.yzu.edu.cn"}
	found := discoverWithGateway(context.Background(), cfg, address.Host, true)

	if found.online || found.captive {
		t.Fatalf("a router admin page was mistaken for the internet or a portal: %#v", found)
	}
	if !found.hasGateway || found.gateway != address.Host {
		t.Fatalf("unexpected gateway state: %#v", found)
	}
	if len(found.failures) != 1 {
		t.Fatalf("expected the configured probe failure to be recorded, got %#v", found.failures)
	}
}

// When the portal is hosted on the gateway it answers with the full
// /eportal/index.jsp session query, which is the address the login flow needs.
func TestDiscoverUsesGatewayPortalAddress(t *testing.T) {
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/eportal/index.jsp?wlanuserip=1&mac=2")
		w.WriteHeader(http.StatusFound)
	}))
	defer gateway.Close()
	useIPProbes(t)

	address, err := url.Parse(gateway.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{ProbeURL: unreachableURL(t), PortalHost: "sso.yzu.edu.cn"}
	found := discoverWithGateway(context.Background(), cfg, address.Host, true)

	want := gateway.URL + "/eportal/index.jsp?wlanuserip=1&mac=2"
	if !found.captive || found.portalURL != want {
		t.Fatalf("unexpected portal address: %#v", found)
	}
}

// The safety rule of the recovery path: the adapter may only be dropped when the
// routing table is genuinely empty. A resolvable gateway means the link is fine,
// so at most the resolver cache may be cleared.
func TestRecoveryStepNeverDropsTheLeaseWhileAGatewayExists(t *testing.T) {
	dnsFailure := probeFailure{kind: "DNS 解析失败", err: errors.New("lookup probe.test: no such host")}
	linkFailure := probeFailure{kind: "连接超时", err: errors.New("context deadline exceeded")}
	cases := []struct {
		name   string
		failed discovery
		want   recoveryStep
	}{
		{
			"gateway present, resolver broken",
			discovery{gateway: "10.0.0.1", hasGateway: true, failures: []probeFailure{dnsFailure}},
			recoveryFlushDNS,
		},
		{
			"gateway present, link merely slow",
			discovery{gateway: "10.0.0.1", hasGateway: true, failures: []probeFailure{linkFailure}},
			recoveryNone,
		},
		{
			"gateway present, mixed failures including DNS",
			discovery{gateway: "10.0.0.1", hasGateway: true, failures: []probeFailure{linkFailure, dnsFailure}},
			recoveryFlushDNS,
		},
		{
			"no default route at all",
			discovery{failures: []probeFailure{linkFailure}},
			recoveryRestartDHCP,
		},
		{
			"no default route and a broken resolver",
			discovery{failures: []probeFailure{dnsFailure}},
			recoveryRestartDHCP,
		},
	}
	for _, testCase := range cases {
		if got := recoveryFor(testCase.failed); got != testCase.want {
			t.Errorf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestDHCPGateThrottlesRestarts(t *testing.T) {
	gate := &dhcpGate{}
	now := time.Now()
	if !gate.allow(now, time.Minute) {
		t.Fatal("the first restart was refused")
	}
	if gate.allow(now.Add(30*time.Second), time.Minute) {
		t.Fatal("a second restart was allowed inside the cooldown window")
	}
	if !gate.allow(now.Add(90*time.Second), time.Minute) {
		t.Fatal("a restart was still refused after the cooldown window")
	}
}

// countingLogin fails the way the reported outage did: the request never
// completes, so nothing was authenticated and the attempt is safe to repeat.
type countingLogin struct{ calls int }

func (c *countingLogin) Login(context.Context, Config, string, string, string) error {
	c.calls++
	return errors.New("net/http: TLS handshake timeout")
}

// The reported outage: the sign-in submission dies on a TLS handshake the portal
// is still gating. Waiting a whole probe interval for the next tick left the
// machine offline for minutes, so one cycle now retries in place.
func TestPerformLoginRetriesAFailedSubmissionInTheSameCycle(t *testing.T) {
	previousDelay := loginRetryDelay
	loginRetryDelay = time.Millisecond
	t.Cleanup(func() { loginRetryDelay = previousDelay })

	dir := t.TempDir()
	store, err := newConfigStore(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.update(configUpdate{
		Username: "student-id", Password: "secret", ProbeURL: "https://example.test/probe",
		PortalHost: "sso.yzu.edu.cn", IntervalSeconds: 60,
	}); err != nil {
		t.Fatal(err)
	}
	logger, err := newLogger(filepath.Join(dir, "app.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	fake := &countingLogin{}
	monitor := &Monitor{configs: store, logger: logger, statuses: &statusStore{}, login: fake}
	monitor.performLogin(context.Background(), store.snapshot(), "http://10.0.0.1/eportal/index.jsp?wlanuserip=1")

	if fake.calls != loginAttempts {
		t.Fatalf("a submission that never completed was tried %d times, want %d", fake.calls, loginAttempts)
	}
	if got := monitor.statuses.get().State; got != "login_failed" {
		t.Fatalf("unexpected status once the retries were exhausted: %q", got)
	}
}

// The default transport gives up a TLS handshake after ten seconds, which is
// what produced "TLS handshake timeout" while the portal was still gating
// traffic.
func TestPortalHTTPClientRaisesTheTLSHandshakeCeiling(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := portalHTTPClient(jar)
	if client.Jar != jar {
		t.Fatal("the sign-in client dropped the cookie jar the flow depends on")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.Transport)
	}
	if transport.TLSHandshakeTimeout <= 10*time.Second {
		t.Fatalf("the TLS handshake ceiling was not raised above the 10s default: %s", transport.TLSHandshakeTimeout)
	}
}
