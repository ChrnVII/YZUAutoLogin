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

const (
	yzuServiceName  = "电信互联网服务"
	browserUA       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
	portalReadyWait = 2 * time.Second
)

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

func (yzuPortalLogin) Login(ctx context.Context, _ Config, username, password, portalURL string) error {
	entryURL, err := url.Parse(portalURL)
	if err != nil {
		return fmt.Errorf("门户地址无效: %w", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar, Timeout: 18 * time.Second}
	seedPortalServiceCookies(client, entryURL)
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
	seedPortalServiceCookies(client, portalPage)
	if err := initializePortalService(ctx, client, portalPage); err != nil {
		return err
	}
	if err := waitForPortalReady(ctx); err != nil {
		return err
	}
	if err := submitPortalService(ctx, client, portalPage, username); err != nil {
		return err
	}
	return nil
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
// preferences, not SSO credentials; their values come from the captured HAR.
func seedPortalServiceCookies(client *http.Client, portalURL *url.URL) {
	if client == nil || client.Jar == nil || portalURL == nil || !strings.Contains(portalURL.Path, "/eportal/") {
		return
	}
	cookieURL := &url.URL{Scheme: portalURL.Scheme, Host: portalURL.Host, Path: "/"}
	encodedService := url.QueryEscape(yzuServiceName)
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

func submitPortalService(ctx context.Context, client *http.Client, portalPage *url.URL, username string) error {
	portalBase := &url.URL{Scheme: portalPage.Scheme, Host: portalPage.Host, Path: "/eportal/InterFace.do"}
	queryString := portalPage.RawQuery
	if queryString == "" {
		return errors.New("校园网门户地址缺少网络会话参数")
	}
	form := url.Values{
		// The portal JavaScript applies encodeURIComponent twice and writes the
		// result directly to the request body. Values.Encode supplies the outer
		// form-encoding pass here, so these values must be pre-escaped only once.
		// Pre-escaping twice would produce a third layer and prevent the portal
		// from recovering wlanacname/nasip, which it reports as an unregistered
		// WEB authentication device.
		"userId":          {url.QueryEscape(username)},
		"flag":            {"casauthofservicecheck"},
		"service":         {url.QueryEscape(yzuServiceName)},
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
		return fmt.Errorf("提交电信服务认证失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("读取电信服务认证响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("电信服务认证失败，HTTP %d", resp.StatusCode)
	}
	if reason, rejected := portalServiceRejection(body); rejected {
		sessionInfo := portalSessionDiagnostics(client, portalPage)
		if reason != "" {
			return fmt.Errorf("电信服务认证被门户拒绝：%s（%s）", reason, sessionInfo)
		}
		return fmt.Errorf("电信服务认证被门户拒绝（门户未提供文字原因；%s）", sessionInfo)
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
