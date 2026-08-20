package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
		if r.PostForm.Get("service") != url.QueryEscape(yzuServiceName) {
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
	if err := submitPortalService(context.Background(), server.Client(), portalPage, "student@example"); err != nil {
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
	seedPortalServiceCookies(client, portalURL)
	cookies := client.Jar.Cookies(portalURL)
	values := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		values[cookie.Name] = cookie.Value
	}
	if values["EPORTAL_COOKIE_SERVER"] != url.QueryEscape(yzuServiceName) || values["EPORTAL_COOKIE_SERVER_NAME"] != url.QueryEscape(yzuServiceName) || values["EPORTAL_COOKIE_DOMAIN"] != "false" {
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
		if cookie, _ := r.Cookie("EPORTAL_COOKIE_SERVER"); cookie.Value != url.QueryEscape(yzuServiceName) {
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
	seedPortalServiceCookies(client, serverURL)
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
	seedPortalServiceCookies(client, portalURL)
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
	err = submitPortalService(context.Background(), server.Client(), portalPage, "student-id")
	if err == nil || !strings.Contains(err.Error(), "当前账号已有在线会话") {
		t.Fatalf("unexpected rejection error: %v", err)
	}
}
