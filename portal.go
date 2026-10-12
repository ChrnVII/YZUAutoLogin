package main

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// portalServices are the carrier services offered on the campus portal's
// service-selection page, in the order the page lists them. The WebUI renders
// this list as a dropdown and the chosen value is sent twice: as the eportal
// preference cookies and as the service field of the loginOfCas request. Both
// must match the portal's wording exactly, so this list is the single source of
// truth for the value.
var portalServices = []string{
	"联通互联网服务",
	"移动互联网服务",
	"电信互联网服务",
}

// defaultPortalService preserves the behaviour of every earlier build, which
// always authenticated against the telecom service. A config file written
// before the selector existed resolves to this value on load.
const defaultPortalService = "电信互联网服务"

const (
	browserUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
	portalReadyWait = 2 * time.Second
	// portalTLSHandshakeTimeout replaces the transport default of 10 seconds.
	// While the machine is still unauthenticated the portal frequently holds the
	// TLS handshake to the SSO host open, and the login was abandoned with
	// "net/http: TLS handshake timeout" even though a retry seconds later
	// succeeded.
	portalTLSHandshakeTimeout = 20 * time.Second
	// portalRequestTimeout bounds one request of the sign-in flow.
	portalRequestTimeout = 18 * time.Second
)

// isPortalService reports whether name is one of the services the portal offers.
func isPortalService(name string) bool {
	for _, service := range portalServices {
		if service == name {
			return true
		}
	}
	return false
}

// normalizeService maps an empty or unrecognized selection onto the default.
// A blank value must keep the previous telecom behaviour rather than failing
// every login, which is what makes an older config file load cleanly.
func normalizeService(name string) string {
	name = strings.TrimSpace(name)
	if isPortalService(name) {
		return name
	}
	return defaultPortalService
}

type yzuPortalLogin struct{}

type ssoPage struct {
	loginType string
	cryptoKey []byte
	flowKey   string
}

var (
	paragraphPattern = regexp.MustCompile(`(?is)<p\b[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>(.*?)</p>`)
	ssoLoginPattern  = regexp.MustCompile(`(?i)https?://sso\.yzu\.edu\.cn/login[^\s"'<]*`)
	eportalPattern   = regexp.MustCompile(`(?i)https?://[^\s"'<]+/eportal/index\.jsp[^\s"'<]*`)
)

func (yzuPortalLogin) Login(ctx context.Context, cfg Config, username, password, portalURL string) error {
	// The carrier service is part of the portal handshake rather than the SSO
	// exchange, so it has to be resolved before the first eportal request.
	service := normalizeService(cfg.Service)
	entryURL, err := url.Parse(portalURL)
	if err != nil {
		return fmt.Errorf("门户地址无效: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := portalHTTPClient(jar)
	seedPortalServiceCookies(client, entryURL, service)
	loginURL, err := resolveSSOLogin(ctx, client, entryURL)
	if err != nil {
		return err
	}

	page, err := getSSOPage(ctx, client, loginURL)
	if err != nil {
		return err
	}
	portalPage, err := submitSSOLogin(ctx, client, loginURL, page, username, password)
	if err != nil {
		return err
	}
	if !strings.Contains(portalPage.Path, "/eportal/") || portalPage.RawQuery == "" {
		return fmt.Errorf("统一认证没有跳转到校园网门户，当前地址为 %s", portalPage.String())
	}
	seedPortalServiceCookies(client, portalPage, service)
	if err := initializePortalService(ctx, client, portalPage); err != nil {
		return err
	}
	if err := waitForPortalReady(ctx); err != nil {
		return err
	}
	if err := submitPortalService(ctx, client, portalPage, username, service); err != nil {
		return err
	}
	return nil
}

// portalHTTPClient builds the client that carries the whole sign-in flow. One
// client serves the redirect chain, the SSO page and the eportal calls, so the
// cookie jar and the connection pool stay shared across all of them.
//
// It exists for one reason: the default transport abandons a TLS handshake after
// ten seconds. While the machine is unauthenticated the portal routinely holds
// the handshake to the SSO host open for longer, which surfaced as
// "net/http: TLS handshake timeout" and left the machine signing in again only
// on the next probe tick — minutes later at a typical interval. Only that
// ceiling is raised here; the rest of the default transport, proxy support
// included, is kept as it was.
func portalHTTPClient(jar http.CookieJar) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = portalTLSHandshakeTimeout
	return &http.Client{Jar: jar, Transport: transport, Timeout: portalRequestTimeout}
}

func resolveSSOLogin(ctx context.Context, client *http.Client, entryURL *url.URL) (*url.URL, error) {
	current := entryURL
	for hops := 0; hops < 4; hops++ {
		if strings.EqualFold(current.Hostname(), "sso.yzu.edu.cn") && current.Path == "/login" {
			return current, nil
		}
		redirectClient := *client
		redirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", browserUA)
		resp, err := redirectClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("获取门户登录地址失败: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()
		if location := resp.Header.Get("Location"); location != "" {
			if next, err := current.Parse(location); err == nil {
				current = next
				continue
			}
		}
		if portalURL := findPortalEntryURL(string(body)); portalURL != "" {
			parsed, _ := url.Parse(portalURL)
			if strings.EqualFold(parsed.Hostname(), "sso.yzu.edu.cn") && parsed.Path == "/login" {
				return parsed, nil
			}
			current = parsed
			continue
		}
		break
	}
	return nil, fmt.Errorf("门户页面未提供统一认证登录地址，当前为 %s", entryURL.Host)
}

func findSSOLoginURL(document string) string {
	document = normalizePortalDocument(document)
	match := ssoLoginPattern.FindString(document)
	if match == "" {
		return ""
	}
	parsed, err := url.Parse(match)
	if err != nil || !strings.EqualFold(parsed.Hostname(), "sso.yzu.edu.cn") || parsed.Path != "/login" {
		return ""
	}
	return parsed.String()
}

func findPortalEntryURL(document string) string {
	document = normalizePortalDocument(document)
	if ssoURL := findSSOLoginURL(document); ssoURL != "" {
		return ssoURL
	}
	match := eportalPattern.FindString(document)
	if match == "" {
		return ""
	}
	parsed, err := url.Parse(match)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !strings.EqualFold(parsed.Path, "/eportal/index.jsp") || parsed.RawQuery == "" {
		return ""
	}
	return parsed.String()
}

func normalizePortalDocument(document string) string {
	return strings.ReplaceAll(html.UnescapeString(document), `\/`, "/")
}

func getSSOPage(ctx context.Context, client *http.Client, loginURL *url.URL) (ssoPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL.String(), nil)
	if err != nil {
		return ssoPage{}, err
	}
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		return ssoPage{}, fmt.Errorf("打开统一认证页面失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ssoPage{}, fmt.Errorf("打开统一认证页面失败，HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return ssoPage{}, err
	}
	values := pageValues(string(body))
	cryptoText := values["login-croypto"]
	cryptoKey, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil || len(cryptoKey) != aes.BlockSize {
		return ssoPage{}, errors.New("统一认证页面缺少有效的加密密钥")
	}
	flowKey := values["login-page-flowkey"]
	if flowKey == "" {
		return ssoPage{}, errors.New("统一认证页面缺少登录会话标识")
	}
	loginType := values["current-login-type"]
	if loginType == "" {
		loginType = "UsernamePassword"
	}
	return ssoPage{loginType: loginType, cryptoKey: cryptoKey, flowKey: flowKey}, nil
}

func submitSSOLogin(ctx context.Context, client *http.Client, loginURL *url.URL, page ssoPage, username, password string) (*url.URL, error) {
	encryptedPassword, err := aesECBEncrypt(page.cryptoKey, []byte(password))
	if err != nil {
		return nil, err
	}
	captchaPayload, err := aesECBEncrypt(page.cryptoKey, []byte("{}"))
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"username":        {username},
		"type":            {page.loginType},
		"_eventId":        {"submit"},
		"geolocation":     {""},
		"execution":       {page.flowKey},
		"captcha_code":    {""},
		"croypto":         {base64.StdEncoding.EncodeToString(page.cryptoKey)},
		"password":        {encryptedPassword},
		"captcha_payload": {captchaPayload},
	}
	postURL := &url.URL{Scheme: loginURL.Scheme, Host: loginURL.Host, Path: "/login"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", loginURL.Scheme+"://"+loginURL.Host)
	req.Header.Set("Referer", loginURL.String())
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("提交统一认证登录失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if strings.EqualFold(resp.Request.URL.Hostname(), loginURL.Hostname()) || strings.Contains(string(body), "login-page-flowkey") {
		return nil, errors.New("统一认证未通过；请检查账号密码，或在网页中完成验证码后重试")
	}
	return resp.Request.URL, nil
}

// seedPortalServiceCookies reproduces the service-selection state that the
// browser sends to eportal before it calls loginOfCas. These are portal-local
// preferences, not SSO credentials; their values come from the captured HAR,
// with the service name coming from the WebUI selection.
func seedPortalServiceCookies(client *http.Client, portalURL *url.URL, service string) {
	if client == nil || client.Jar == nil || portalURL == nil || !strings.Contains(portalURL.Path, "/eportal/") {
		return
	}
	cookieURL := &url.URL{Scheme: portalURL.Scheme, Host: portalURL.Host, Path: "/"}
	encodedService := url.QueryEscape(normalizeService(service))
	client.Jar.SetCookies(cookieURL, []*http.Cookie{
		{Name: "EPORTAL_COOKIE_OPERATORPWD", Value: "", Path: "/"},
		{Name: "EPORTAL_COOKIE_SERVER", Value: encodedService, Path: "/"},
		{Name: "EPORTAL_COOKIE_SERVER_NAME", Value: encodedService, Path: "/"},
		{Name: "EPORTAL_COOKIE_DOMAIN", Value: "false", Path: "/"},
	})
}

// initializePortalService reproduces the two requests made when the browser
// opens the service-selection page. The portal uses them to initialize the
// current web-authentication device before it accepts loginOfCas.
func initializePortalService(ctx context.Context, client *http.Client, portalPage *url.URL) error {
	queryString := portalPage.RawQuery
	if queryString == "" {
		return errors.New("校园网门户地址缺少网络会话参数")
	}
	if err := callPortalInterface(ctx, client, portalPage, "pageInfo", nil, url.Values{"queryString": {queryString}}); err != nil {
		return fmt.Errorf("初始化校园网服务页面失败（pageInfo）: %w", err)
	}
	if err := callPortalInterface(ctx, client, portalPage, "getServices", url.Values{"queryString": {queryString}}, nil); err != nil {
		return fmt.Errorf("初始化校园网服务列表失败（getServices）: %w", err)
	}
	if err := callPortalInterface(ctx, client, portalPage, "getOnlineUserInfo", nil, url.Values{"userIndex": {""}}); err != nil {
		return fmt.Errorf("初始化校园网在线状态失败（getOnlineUserInfo）: %w", err)
	}
	return nil
}

func waitForPortalReady(ctx context.Context) error {
	timer := time.NewTimer(portalReadyWait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// callPortalInterface sends a POST using the request placement captured in
// the browser HAR: pageInfo and getOnlineUserInfo receive form fields, while
// getServices receives queryString in the URL query.
func callPortalInterface(ctx context.Context, client *http.Client, portalPage *url.URL, method string, extraQuery, form url.Values) error {
	endpoint := &url.URL{Scheme: portalPage.Scheme, Host: portalPage.Host, Path: "/eportal/InterFace.do"}
	query := url.Values{"method": {method}}
	for key, values := range extraQuery {
		query[key] = append([]string(nil), values...)
	}
	endpoint.RawQuery = query.Encode()
	var body io.Reader = strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Origin", portalPage.Scheme+"://"+portalPage.Host)
	req.Header.Set("Referer", portalPage.String())
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)); err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func submitPortalService(ctx context.Context, client *http.Client, portalPage *url.URL, username, service string) error {
	portalBase := &url.URL{Scheme: portalPage.Scheme, Host: portalPage.Host, Path: "/eportal/InterFace.do"}
	queryString := portalPage.RawQuery
	if queryString == "" {
		return errors.New("校园网门户地址缺少网络会话参数")
	}
	selectedService := normalizeService(service)
	form := url.Values{
		// The portal JavaScript applies encodeURIComponent twice and writes the
		// result directly to the request body. Values.Encode supplies the outer
		// form-encoding pass here, so these values must be pre-escaped only once.
		// Pre-escaping twice would produce a third layer and prevent the portal
		// from recovering wlanacname/nasip, which it reports as an unregistered
		// WEB authentication device.
		"userId":          {url.QueryEscape(username)},
		"flag":            {"casauthofservicecheck"},
		"service":         {url.QueryEscape(selectedService)},
		"queryString":     {url.QueryEscape(queryString)},
		"operatorPwd":     {""},
		"operatorUserId":  {""},
		"passwordEncrypt": {"false"},
		"rememberService": {"false"},
	}
	endpoint := *portalBase
	endpoint.RawQuery = url.Values{"method": {"loginOfCas"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Origin", portalPage.Scheme+"://"+portalPage.Host)
	req.Header.Set("Referer", portalPage.String())
	req.Header.Set("User-Agent", browserUA)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("提交%s认证失败: %w", selectedService, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("读取%s认证响应失败: %w", selectedService, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s认证失败，HTTP %d", selectedService, resp.StatusCode)
	}
	if reason, rejected := portalServiceRejection(body); rejected {
		sessionInfo := portalSessionDiagnostics(client, portalPage)
		if reason != "" {
			return fmt.Errorf("%s认证被门户拒绝：%s（%s）", selectedService, reason, sessionInfo)
		}
		return fmt.Errorf("%s认证被门户拒绝（门户未提供文字原因；%s）", selectedService, sessionInfo)
	}
	return nil
}

// portalSessionDiagnostics deliberately reports only cookie names and boolean
// state. It helps diagnose portal interoperability without exposing cookie
// values or WLAN session parameters in the log.
func portalSessionDiagnostics(client *http.Client, portalPage *url.URL) string {
	if client == nil || client.Jar == nil || portalPage == nil {
		return "会话诊断不可用"
	}
	cookies := client.Jar.Cookies(portalPage)
	names := make(map[string]bool, len(cookies))
	for _, cookie := range cookies {
		names[cookie.Name] = true
	}
	serviceCookieCount := 0
	for _, name := range []string{"EPORTAL_COOKIE_OPERATORPWD", "EPORTAL_COOKIE_SERVER", "EPORTAL_COOKIE_SERVER_NAME", "EPORTAL_COOKIE_DOMAIN"} {
		if names[name] {
			serviceCookieCount++
		}
	}
	return fmt.Sprintf("JSESSIONID=%t，服务Cookie=%d/4，页面含jsessionid=%t", names["JSESSIONID"], serviceCookieCount, strings.Contains(strings.ToLower(portalPage.Path), ";jsessionid="))
}

// portalServiceRejection extracts only the short, user-facing rejection text.
// Full portal responses can include session information, so they must never be
// copied to logs.
func portalServiceRejection(body []byte) (string, bool) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err == nil {
		result := strings.ToLower(strings.TrimSpace(jsonString(payload["result"])))
		if result == "fail" || result == "error" {
			for _, key := range []string{"message", "msg", "errorMessage", "error"} {
				if message := sanitizePortalMessage(jsonString(payload[key])); message != "" {
					return message, true
				}
			}
			return "", true
		}
	}

	// Older portal pages send JSON with a text/html content type. Preserve the
	// previous detection as a fallback, but do not log their full body.
	response := strings.ToLower(string(body))
	if strings.Contains(response, `"result":"fail"`) || strings.Contains(response, `"result":"error"`) {
		return "", true
	}
	return "", false
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

func sanitizePortalMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	const maxRunes = 200
	runes := []rune(message)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + "…"
	}
	return message
}

func pageValues(document string) map[string]string {
	values := make(map[string]string)
	for _, match := range paragraphPattern.FindAllStringSubmatch(document, -1) {
		values[match[1]] = strings.TrimSpace(html.UnescapeString(match[2]))
	}
	return values
}

func aesECBEncrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	for offset := 0; offset < len(padded); offset += block.BlockSize() {
		block.Encrypt(ciphertext[offset:offset+block.BlockSize()], padded[offset:offset+block.BlockSize()])
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}
