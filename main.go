package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/systray"
)

const (
	appName        = "YZU Auto Login"
	defaultWebPort = 8765
)

type Config struct {
	Version             int    `json:"version"`
	Username            string `json:"username"`
	PasswordEncrypted   string `json:"password_encrypted"`
	Service             string `json:"service"`
	ProbeURL            string `json:"probe_url"`
	PortalHost          string `json:"portal_host"`
	ProbeExpectedText   string `json:"probe_expected_text"`
	ProbeExpectedStatus int    `json:"probe_expected_status"`
	IntervalSeconds     int    `json:"interval_seconds"`
	WebPort             int    `json:"web_port"`
}

type configUpdate struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	ClearPassword       bool   `json:"clear_password"`
	Service             string `json:"service"`
	ProbeURL            string `json:"probe_url"`
	PortalHost          string `json:"portal_host"`
	ProbeExpectedText   string `json:"probe_expected_text"`
	ProbeExpectedStatus int    `json:"probe_expected_status"`
	IntervalSeconds     int    `json:"interval_seconds"`
}

func defaultConfig() Config {
	return Config{
		Version:           1,
		Service:           defaultPortalService,
		ProbeURL:          "http://www.msftconnecttest.com/connecttest.txt",
		PortalHost:        "sso.yzu.edu.cn",
		ProbeExpectedText: "Microsoft Connect Test",
		IntervalSeconds:   60,
		WebPort:           defaultWebPort,
	}
}

type ConfigStore struct {
	path string
	key  []byte
	mu   sync.RWMutex
	cfg  Config
}

func newConfigStore(path string) (*ConfigStore, error) {
	keyPath := filepath.Join(filepath.Dir(path), "secret.key")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("初始化本地加密密钥失败: %w", err)
	}
	s := &ConfigStore{path: path, key: key, cfg: defaultConfig()}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}
	if err := json.Unmarshal(data, &s.cfg); err != nil {
		return nil, fmt.Errorf("配置文件格式无效: %w", err)
	}
	// A config written before the service selector existed carries no service
	// field. Resolve it before validation so the file stays loadable, and keep
	// the telecom behaviour every earlier build had.
	s.cfg.Service = normalizeService(s.cfg.Service)
	if err := validateConfig(s.cfg); err != nil {
		return nil, err
	}
	// Old builds stored a DPAPI field, and builds before the service selector
	// wrote no service field at all. Both are normalized on load; save the
	// normalized form so the file on disk matches what the WebUI shows.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil && (raw["password_dpapi"] != nil || raw["service"] == nil) {
		if err := s.saveLocked(); err != nil {
			return nil, fmt.Errorf("迁移配置失败: %w", err)
		}
	}
	return s, nil
}

func validateConfig(cfg Config) error {
	probeURL, err := url.ParseRequestURI(cfg.ProbeURL)
	if err != nil || probeURL.Host == "" || (probeURL.Scheme != "http" && probeURL.Scheme != "https") {
		if err == nil {
			err = errors.New("仅支持 HTTP 或 HTTPS")
		}
		return fmt.Errorf("探测地址无效: %w", err)
	}
	if cfg.PortalHost == "" || strings.Contains(cfg.PortalHost, "/") {
		return errors.New("门户主机名无效")
	}
	if !isPortalService(cfg.Service) {
		return fmt.Errorf("运营商服务无效，可选值为 %s", strings.Join(portalServices, "、"))
	}
	if len(cfg.ProbeExpectedText) > 512 {
		return errors.New("预期探测正文不能超过 512 个字符")
	}
	if cfg.ProbeExpectedStatus != 0 && (cfg.ProbeExpectedStatus < 100 || cfg.ProbeExpectedStatus > 599) {
		return errors.New("预期状态码必须是 100 到 599 之间的数字，留空或 0 表示不校验")
	}
	if cfg.IntervalSeconds < 15 || cfg.IntervalSeconds > 86400 {
		return errors.New("探测间隔必须在 15 到 86400 秒之间")
	}
	if cfg.WebPort < 1024 || cfg.WebPort > 65535 {
		return errors.New("WebUI 端口无效")
	}
	return nil
}

func (s *ConfigStore) snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *ConfigStore) update(update configUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.cfg
	cfg.Username = strings.TrimSpace(update.Username)
	cfg.PortalHost = strings.TrimSpace(update.PortalHost)
	// An unknown or blank selection falls back to the default service instead of
	// silently failing the next login.
	cfg.Service = normalizeService(update.Service)
	cfg.ProbeURL = strings.TrimSpace(update.ProbeURL)
	cfg.ProbeExpectedText = strings.TrimSpace(update.ProbeExpectedText)
	cfg.ProbeExpectedStatus = update.ProbeExpectedStatus
	cfg.IntervalSeconds = update.IntervalSeconds
	if update.ClearPassword {
		cfg.PasswordEncrypted = ""
	} else if update.Password != "" {
		encrypted, err := encryptPassword(s.key, update.Password)
		if err != nil {
			return fmt.Errorf("加密密码失败: %w", err)
		}
		cfg.PasswordEncrypted = encrypted
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	s.cfg = cfg
	return s.saveLocked()
}

func (s *ConfigStore) credentials() (string, string, error) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if cfg.Username == "" || cfg.PasswordEncrypted == "" {
		return "", "", errors.New("尚未配置账号或密码")
	}
	plaintext, err := decryptPassword(s.key, cfg.PasswordEncrypted)
	if err != nil {
		return "", "", fmt.Errorf("无法解密密码（请确认 secret.key 未被替换）: %w", err)
	}
	return cfg.Username, plaintext, nil
}

func (s *ConfigStore) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// A separate random key keeps the password unreadable in config.json without
// requiring a Windows account binding or an interactive unlock step.
func loadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("secret.key 长度无效")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptPassword(key []byte, password string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// Prefixing the nonce makes each encrypted value self-contained.
	ciphertext := gcm.Seal(nonce, nonce, []byte(password), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptPassword(key []byte, encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("加密密码格式无效")
	}
	plaintext, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

const maxLogEntries = 300

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

type AppLogger struct {
	mu      sync.Mutex
	l       *log.Logger
	f       *os.File
	entries []LogEntry
}

func newLogger(path string) (*AppLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	entries, err := readRecentLogEntries(path, maxLogEntries)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &AppLogger{l: log.New(f, "", log.Ldate|log.Ltime|log.Lmicroseconds), f: f, entries: entries}, nil
}

func (l *AppLogger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	message := fmt.Sprintf(format, args...)
	l.l.Print(message)
	l.entries = append(l.entries, LogEntry{Timestamp: time.Now(), Message: message})
	if len(l.entries) > maxLogEntries {
		l.entries = l.entries[len(l.entries)-maxLogEntries:]
	}
}

func (l *AppLogger) Entries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]LogEntry, len(l.entries))
	copy(entries, l.entries)
	return entries
}

func (l *AppLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

func readRecentLogEntries(path string, limit int) ([]LogEntry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const maxRead = 64 * 1024
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	offset := int64(0)
	if info.Size() > maxRead {
		offset = info.Size() - maxRead
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if offset > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	entries := make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		entry := LogEntry{Message: line}
		if len(line) > 27 {
			if timestamp, err := time.ParseInLocation("2006/01/02 15:04:05.000000", line[:26], time.Local); err == nil {
				entry.Timestamp = timestamp
				entry.Message = strings.TrimSpace(line[26:])
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

type Status struct {
	State       string    `json:"state"`
	Message     string    `json:"message"`
	LastChecked time.Time `json:"last_checked"`
	PortalURL   string    `json:"portal_url,omitempty"`
}

type statusStore struct {
	mu sync.RWMutex
	v  Status
}

func (s *statusStore) get() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

func (s *statusStore) set(v Status) {
	s.mu.Lock()
	s.v = v
	s.mu.Unlock()
}

type probeResult struct {
	portalURL string
	redirect  bool
	captive   bool
}

func portalEntryURL(u *url.URL, cfg Config) string {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	if strings.EqualFold(u.Hostname(), cfg.PortalHost) {
		return u.String()
	}
	// Captive portals commonly redirect the connectivity test to this gateway
	// first. It carries the WLAN session query that resolveSSOLogin must retain.
	if strings.EqualFold(u.Path, "/eportal/index.jsp") && u.RawQuery != "" {
		return u.String()
	}
	return ""
}

// probe checks the connectivity probe configured in the WebUI.
func probe(ctx context.Context, cfg Config) (probeResult, error) {
	return probeTargetURL(ctx, cfg, configuredProbeTarget(cfg))
}

// probeTargetURL checks one candidate address. Splitting the target out lets the
// same detection rules serve the configured probe, the default gateway and the
// IP-literal fallbacks, which differ only in their expected body, status and
// timeout.
func probeTargetURL(ctx context.Context, cfg Config, target probeTarget) (probeResult, error) {
	client := &http.Client{
		Timeout: target.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	current, err := url.Parse(target.url)
	if err != nil {
		return probeResult{}, err
	}
	for redirects := 0; redirects < 5; redirects++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return probeResult{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return probeResult{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()
		if entryURL := portalEntryURL(resp.Request.URL, cfg); entryURL != "" {
			return probeResult{portalURL: entryURL, redirect: redirects > 0, captive: true}, nil
		}
		if location := resp.Header.Get("Location"); location != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if target, err := resp.Request.URL.Parse(location); err == nil {
				if entryURL := portalEntryURL(target, cfg); entryURL != "" {
					return probeResult{portalURL: entryURL, redirect: true, captive: true}, nil
				}
				current = target
				continue
			}
		}
		bodyText := string(body)
		unexpectedStatus := target.expectedStatus != 0 && resp.StatusCode != target.expectedStatus
		unexpectedResponse := target.expectedText != "" && (resp.StatusCode != http.StatusOK || strings.TrimSpace(bodyText) != target.expectedText)
		if unexpectedStatus || unexpectedResponse || strings.Contains(strings.ToLower(bodyText), strings.ToLower(cfg.PortalHost)) {
			if entryURL := findPortalEntryURL(bodyText); entryURL != "" {
				return probeResult{portalURL: entryURL, captive: true}, nil
			}
			return probeResult{captive: true}, nil
		}
		return probeResult{}, nil
	}
	return probeResult{captive: true}, nil
}

type loginExecutor interface {
	Login(context.Context, Config, string, string, string) error
}

type Monitor struct {
	configs  *ConfigStore
	logger   *AppLogger
	statuses *statusStore
	login    loginExecutor
	mu       sync.Mutex
	cancel   context.CancelFunc
	checking sync.Mutex
	// dhcp throttles the destructive lease restart so a short probe interval
	// cannot drop the adapter repeatedly while a restart is still converging.
	dhcp dhcpGate
}

func (m *Monitor) Start() {
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.mu.Unlock()
	go m.loop(ctx)
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.mu.Unlock()
}

func (m *Monitor) Restart() { m.Stop(); m.Start() }

func (m *Monitor) CheckNow() { go m.check(context.Background()) }

func (m *Monitor) loop(ctx context.Context) {
	m.check(ctx)
	cfg := m.configs.snapshot()
	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

// check runs one full probe cycle: discover the portal, sign in when one is
// found, and fall back to network recovery when nothing can be reached at all.
func (m *Monitor) check(ctx context.Context) {
	// A recovery pass can take minutes, so a cycle that is still running absorbs
	// the next tick instead of queueing a second pass behind it.
	if !m.checking.TryLock() {
		return
	}
	defer m.checking.Unlock()

	cfg := m.configs.snapshot()
	m.statuses.set(Status{State: "checking", Message: "正在探测网络…", LastChecked: time.Now()})
	found := discoverPortal(ctx, cfg)
	if ctx.Err() != nil {
		return
	}

	if found.online {
		m.reportOnline(cfg, found)
		return
	}
	if found.portalURL != "" {
		m.performLogin(ctx, cfg, found.portalURL)
		return
	}
	if len(found.failures) == 0 {
		m.logger.Printf("检测到门户拦截，但未能从重定向中发现登录地址；将在下个探测周期重试")
		m.statuses.set(Status{State: "portal_discovery_failed", Message: "检测到门户拦截，正在等待发现登录地址", LastChecked: time.Now()})
		return
	}

	m.logger.Printf("探测失败：%s", found.failureSummary())
	recovered := m.recoverNetwork(ctx, cfg, found)
	if ctx.Err() != nil {
		return
	}
	switch {
	case recovered.online:
		m.logger.Printf("网络已恢复")
		m.statuses.set(Status{State: "online", Message: "网络已恢复", LastChecked: time.Now()})
	case recovered.portalURL != "":
		m.performLogin(ctx, cfg, recovered.portalURL)
	default:
		m.statuses.set(Status{State: "offline", Message: "探测失败：" + found.failureKinds(), LastChecked: time.Now()})
	}
}

// reportOnline records a healthy cycle. A healthy result that only an IP literal
// could produce still means the resolver is broken, so that case is named in the
// status instead of being hidden behind a plain success message.
func (m *Monitor) reportOnline(cfg Config, found discovery) {
	message := "网络正常"
	if found.primaryFailureKind != "" {
		message = fmt.Sprintf("网络正常（%s 探测失败：%s，已由 IP 直连探测确认连通）", cfg.ProbeURL, found.primaryFailureKind)
	}
	m.logger.Printf("%s", message)
	m.statuses.set(Status{State: "online", Message: message, LastChecked: time.Now()})
}

// recoverNetwork applies the cheapest remedy that can plausibly explain the
// failure it was given. The escalation itself is decided by recoveryFor, which
// keeps the safety rule — never drop the lease while a default route exists —
// enforced in one explicit, testable place.
func (m *Monitor) recoverNetwork(ctx context.Context, cfg Config, failed discovery) discovery {
	if !networkRecoveryAvailable {
		return failed
	}

	switch recoveryFor(failed) {
	case recoveryFlushDNS:
		if !flushDNS(ctx) {
			return failed
		}
		m.logger.Printf("网关 %s 可用但域名解析失败，已清理 DNS 缓存并重新探测", failed.gateway)
		return discoverPortal(ctx, cfg)

	case recoveryRestartDHCP:
		if !m.dhcp.allow(time.Now(), dhcpRestartCooldown) {
			m.logger.Printf("未获取到默认网关，但距上次重启 DHCP 不足 %s；跳过本次重启，避免网络反复中断", dhcpRestartCooldown)
			return failed
		}
		m.logger.Printf("未检测到默认网关，执行 ipconfig /release 与 ipconfig /renew")
		renewCtx, cancel := context.WithTimeout(ctx, dhcpRestartTimeout)
		err := restartDHCP(renewCtx)
		cancel()
		if err != nil {
			m.logger.Printf("执行 ipconfig /release 与 ipconfig /renew 失败：%v", err)
			return failed
		}
		m.logger.Printf("已执行 ipconfig /release 与 ipconfig /renew，等待网络收敛（最多 %s）", gatewayWaitTimeout)
		waitCtx, cancel := context.WithTimeout(ctx, gatewayWaitTimeout)
		gateway, ok := waitForGateway(waitCtx)
		cancel()
		if !ok {
			m.logger.Printf("运行 ipconfig /release 与 ipconfig /renew 后仍未获取到网关")
			return failed
		}
		m.logger.Printf("已重新获取默认网关 %s，重新探测", gateway)
		return discoverPortal(ctx, cfg)
	}
	return failed
}

// performLogin runs the portal sign-in flow for a discovered portal address.
func (m *Monitor) performLogin(ctx context.Context, cfg Config, portalURL string) {
	m.logger.Printf("检测到校园网门户: %s", portalURL)
	m.statuses.set(Status{State: "logging_in", Message: "检测到门户，正在登录…", LastChecked: time.Now(), PortalURL: portalURL})
	username, password, err := m.configs.credentials()
	if err != nil {
		m.logger.Printf("未尝试登录: %v", err)
		m.statuses.set(Status{State: "needs_configuration", Message: "请在 WebUI 配置账号和密码", LastChecked: time.Now(), PortalURL: portalURL})
		return
	}
	loginCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = m.login.Login(loginCtx, cfg, username, password, portalURL)
	cancel()
	if err == nil {
		m.logger.Printf("已提交登录，正在验证网络状态")
		m.statuses.set(Status{State: "verifying", Message: "已提交登录，正在验证…", LastChecked: time.Now()})
		verifyTimer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			verifyTimer.Stop()
			return
		case <-verifyTimer.C:
		}
		verifyCtx, verifyCancel := context.WithTimeout(ctx, 12*time.Second)
		verify := discoverPortal(verifyCtx, cfg)
		verifyCancel()
		switch {
		case verify.online:
			m.logger.Printf("登录成功，网络已恢复")
			m.statuses.set(Status{State: "online", Message: "登录成功，网络正常", LastChecked: time.Now()})
			return
		case verify.captive:
			err = errors.New("登录后的网络验证仍被重定向至门户")
		default:
			err = fmt.Errorf("登录后的网络验证失败：%s", verify.failureKinds())
		}
	}
	m.logger.Printf("登录失败：%v；将在下个探测周期重试", err)
	m.statuses.set(Status{State: "login_failed", Message: "登录失败，将在下个周期重试：" + err.Error(), LastChecked: time.Now(), PortalURL: portalURL})
}

type App struct {
	baseDir  string
	configs  *ConfigStore
	logger   *AppLogger
	statuses statusStore
	monitor  *Monitor
	server   *http.Server
	url      string
	quitOnce sync.Once
	statusMI *systray.MenuItem
}

func newApp(baseDir string) (*App, error) {
	configs, err := newConfigStore(filepath.Join(baseDir, "config.json"))
	if err != nil {
		return nil, err
	}
	logger, err := newLogger(filepath.Join(baseDir, "logs", "app.log"))
	if err != nil {
		return nil, err
	}
	a := &App{baseDir: baseDir, configs: configs, logger: logger, statuses: statusStore{v: Status{State: "starting", Message: "正在启动"}}}
	a.monitor = &Monitor{configs: configs, logger: logger, statuses: &a.statuses, login: yzuPortalLogin{}}
	return a, nil
}

func (a *App) onReady() {
	systray.SetIcon(trayIcon())
	systray.SetTitle("YZU Auto Login")
	systray.SetTooltip("YZU Auto Login")
	openMI := systray.AddMenuItem("打开 WebUI", "在默认浏览器打开本机管理页面")
	a.statusMI = systray.AddMenuItem("状态：启动中", "")
	a.statusMI.Disable()
	probeMI := systray.AddMenuItem("立即探测", "立即执行一次网络探测")
	systray.AddSeparator()
	quitMI := systray.AddMenuItem("退出", "停止自动探测并退出")

	if err := a.startServer(); err != nil {
		a.logger.Printf("WebUI 启动失败: %v", err)
		a.statuses.set(Status{State: "error", Message: "WebUI 启动失败：" + err.Error()})
	} else {
		a.logger.Printf("程序启动，WebUI: %s", a.url)
	}
	a.monitor.Start()
	go a.refreshTrayStatus()
	go func() {
		for {
			select {
			case <-openMI.ClickedCh:
				a.openWebUI()
			case <-probeMI.ClickedCh:
				a.monitor.CheckNow()
			case <-quitMI.ClickedCh:
				systray.Quit()
			}
		}
	}()
}

// trayIcon returns a tiny self-contained 16×16 Windows ICO: blue background with a white Y.
// Keeping it in code avoids requiring any extra asset beside the executable.
func trayIcon() []byte {
	const (
		width       = 16
		dibOffset   = 22
		pixelOffset = dibOffset + 40
		maskSize    = 64 // 16 pixels × 16 rows, padded to a 32-bit boundary
		imageSize   = width * width * 4
	)
	icon := make([]byte, pixelOffset+imageSize+maskSize)
	binary.LittleEndian.PutUint16(icon[2:], 1) // type: icon
	binary.LittleEndian.PutUint16(icon[4:], 1) // one image
	icon[6], icon[7] = width, width
	binary.LittleEndian.PutUint16(icon[10:], 1)
	binary.LittleEndian.PutUint16(icon[12:], 32)
	binary.LittleEndian.PutUint32(icon[14:], uint32(40+imageSize+maskSize))
	binary.LittleEndian.PutUint32(icon[18:], dibOffset)
	binary.LittleEndian.PutUint32(icon[dibOffset:], 40)
	binary.LittleEndian.PutUint32(icon[dibOffset+4:], width)
	binary.LittleEndian.PutUint32(icon[dibOffset+8:], width*2) // XOR + AND bitmap height
	binary.LittleEndian.PutUint16(icon[dibOffset+12:], 1)
	binary.LittleEndian.PutUint16(icon[dibOffset+14:], 32)
	binary.LittleEndian.PutUint32(icon[dibOffset+20:], imageSize)

	for y := 0; y < width; y++ {
		for x := 0; x < width; x++ {
			// DIB rows are stored bottom-up.
			i := pixelOffset + ((width-1-y)*width+x)*4
			whiteY := (y < 7 && (x == 3+y/2 || x == 12-y/2)) || (y >= 7 && x == 8)
			if whiteY {
				icon[i], icon[i+1], icon[i+2], icon[i+3] = 255, 255, 255, 255
			} else {
				icon[i], icon[i+1], icon[i+2], icon[i+3] = 0xAA, 0x69, 0x17, 255 // BGRA #1769AA
			}
		}
	}
	return icon
}

func (a *App) onExit() {
	a.quitOnce.Do(func() {
		a.logger.Printf("程序退出")
		a.monitor.Stop()
		if a.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = a.server.Shutdown(ctx)
		}
	})
}

func (a *App) refreshTrayStatus() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if a.statusMI == nil {
			continue
		}
		status := a.statuses.get()
		a.statusMI.SetTitle("状态：" + status.Message)
	}
}

func (a *App) startServer() error {
	cfg := a.configs.snapshot()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(cfg.WebPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	a.url = "http://" + listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/config", a.handleConfig)
	mux.HandleFunc("/api/logs", a.handleLogs)
	mux.HandleFunc("/api/probe", a.handleProbe)
	a.server = &http.Server{Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := a.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.logger.Printf("WebUI 服务异常: %v", err)
		}
	}()
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.statuses.get())
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := a.configs.snapshot()
		writeJSON(w, http.StatusOK, map[string]any{
			"username": cfg.Username, "has_password": cfg.PasswordEncrypted != "",
			"service": cfg.Service, "services": portalServices, "probe_url": cfg.ProbeURL,
			"portal_host": cfg.PortalHost, "probe_expected_text": cfg.ProbeExpectedText,
			"probe_expected_status": cfg.ProbeExpectedStatus,
			"interval_seconds":      cfg.IntervalSeconds, "web_port": cfg.WebPort,
		})
	case http.MethodPut:
		defer r.Body.Close()
		var update configUpdate
		if err := json.NewDecoder(io.LimitReader(r.Body, 32*1024)).Decode(&update); err != nil {
			writeError(w, http.StatusBadRequest, "配置 JSON 无效")
			return
		}
		if err := a.configs.update(update); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.logger.Printf("配置已更新")
		a.monitor.Restart()
		writeJSON(w, http.StatusOK, map[string]string{"message": "已保存；探测已按新配置重新启动"})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": a.logger.Entries()})
}

func (a *App) handleProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	a.monitor.CheckNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "已开始探测"})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "方法不允许")
}
func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}

func (a *App) openWebUI() {
	if a.url == "" {
		return
	}
	if err := openURL(a.url); err != nil {
		a.logger.Printf("无法打开浏览器: %v", err)
	}
}

func openURL(target string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
}

func main() {
	releaseInstanceLock, err := acquireInstanceLock()
	if errors.Is(err, errAlreadyRunning) {
		// A second launch should be harmless and guide the user to the already
		// running copy instead of creating another monitor.
		_ = openURL(fmt.Sprintf("http://127.0.0.1:%d", defaultWebPort))
		return
	}
	if err != nil {
		panic(err)
	}
	defer releaseInstanceLock()

	baseDir, err := executableDir()
	if err != nil {
		panic(err)
	}
	app, err := newApp(baseDir)
	if err != nil {
		panic(err)
	}
	systray.Run(app.onReady, app.onExit)
}

func executableDir() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(path), nil
}

const indexHTML = `<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>YZU Auto Login</title>
<style>body{max-width:720px;margin:32px auto;padding:0 16px;font:15px system-ui;color:#172033;background:#f7f8fa}section{background:#fff;border:1px solid #dde2e8;border-radius:10px;padding:20px;margin:16px 0}h1{margin:0 0 4px}h2{font-size:18px}label{display:block;margin:12px 0 4px}input,select{box-sizing:border-box;width:100%;padding:9px;border:1px solid #bbc4ce;border-radius:6px;background:#fff;color:inherit;font:inherit}button{padding:9px 14px;border:0;border-radius:6px;background:#1769aa;color:#fff;cursor:pointer;margin:16px 8px 0 0}.state{font-weight:600}.hint,#result{color:#56616e;font-size:13px;white-space:pre-wrap}.logs{max-height:260px;overflow:auto;padding:10px;background:#101828;color:#d0d5dd;border-radius:6px;font:12px ui-monospace,Consolas,monospace;white-space:pre-wrap}.danger{color:#b42318}</style>
<body><h1>YZU Auto Login</h1><div class="hint">仅监听本机。密码以 AES-GCM 加密保存。</div>
<section><h2>状态</h2><div id="status">正在加载…</div><button onclick="probe()">立即探测</button></section>
<section><h2>配置</h2><form id="form"><label>账号</label><input id="username" autocomplete="username"><label>密码（留空则保留原密码）</label><input id="password" type="password" autocomplete="new-password"><label><input id="clear" type="checkbox" style="width:auto"> 删除已保存的密码</label><label>运营商服务</label><select id="service"></select><label>探测地址</label><input id="probe_url" type="url"><label>预期探测正文</label><input id="probe_expected_text"><label>预期状态码（0 表示不校验）</label><input id="probe_expected_status" type="number" min="0" max="599"><label>门户主机名</label><input id="portal_host"><label>探测间隔（秒，至少 15）</label><input id="interval_seconds" type="number" min="15" max="86400"><button>保存配置</button></form><div id="result"></div></section>
<section><h2>日志</h2><div class="hint">每两秒自动刷新；日志文件同时保存在程序目录的 logs\\app.log。</div><pre id="logs" class="logs">正在加载日志…</pre></section>
<script>
const $=id=>document.getElementById(id);const esc=s=>String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
let configLoaded=false;
async function loadConfig(force=false){if(configLoaded&&!force)return;let c=await (await fetch('/api/config')).json();let sel=$('service');if(!sel.options.length)sel.innerHTML=(c.services||[]).map(s=>'<option value="'+esc(s)+'">'+esc(s)+'</option>').join('');['username','service','probe_url','probe_expected_text','probe_expected_status','portal_host','interval_seconds'].forEach(k=>$(k).value=c[k]);$('password').placeholder=c.has_password?'已保存（无需重复填写）':'尚未设置';configLoaded=true}
async function loadStatus(){let s=await (await fetch('/api/status')).json();$('status').innerHTML='<div class="state">'+esc(s.message)+'</div><div class="hint">状态：'+esc(s.state)+'<br>最后探测：'+(s.last_checked?new Date(s.last_checked).toLocaleString():'尚无')+(s.portal_url?'<br>门户：'+esc(s.portal_url):'')+'</div>'}
async function loadLogs(){try{let data=await (await fetch('/api/logs')).json(),el=$('logs'),atBottom=el.scrollTop+el.clientHeight>=el.scrollHeight-20;el.textContent=data.entries.map(e=>(e.timestamp?new Date(e.timestamp).toLocaleString()+' ':'')+e.message).join('\n')||'暂无日志';if(atBottom)el.scrollTop=el.scrollHeight}catch{}}
async function probe(){await fetch('/api/probe',{method:'POST'});setTimeout(loadStatus,500)}
$('form').onsubmit=async e=>{e.preventDefault();let body={username:$('username').value,password:$('password').value,clear_password:$('clear').checked,service:$('service').value,probe_url:$('probe_url').value,probe_expected_text:$('probe_expected_text').value,probe_expected_status:Number($('probe_expected_status').value)||0,portal_host:$('portal_host').value,interval_seconds:Number($('interval_seconds').value)};let r=await fetch('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),x=await r.json();$('result').className=r.ok?'':'danger';$('result').textContent=r.ok?x.message:x.error; if(r.ok){$('password').value='';$('clear').checked=false;await loadConfig(true);loadStatus()}};loadConfig();loadStatus();loadLogs();setInterval(loadStatus,5000);setInterval(loadLogs,2000);
</script></body></html>`
