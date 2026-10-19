package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 自定义节点来源。
//
// 背景：上游只有 VPN Gate 一个公网来源。用户手里可能有别的 OpenVPN 配置
// （自建服务器、朋友分享的、VPNBook 这类公开免费源），这里允许添加最多
// 20 个 HTTPS 来源，支持四种格式：
//
//	ovpn  单个 OpenVPN 配置文件
//	zip   一包 .ovpn 文件（内存里解，不落盘）
//	csv   VPN Gate 格式的节点 CSV
//	json  配置清单，见 jsonSourceDoc
//
// 安全约束（这不是任意文件订阅器）：
//   - 只接受 https，防凭据与配置被中间人掉包；
//   - 下载限时 30 秒、限大小 16MB、重定向最多 5 跳；
//   - 每份配置都要过 validateOvpnConfig，不合格的整条丢弃；
//   - 密码接口不回显，空白编辑保留旧密码；配置、状态与缓存文件 0600 权限。

const (
	maxCustomSources = 20
	sourceFetchTimeout = 30 * time.Second
	maxSourceBytes     = 16 << 20
	maxSourceRedirects = 5
	maxZipEntries      = 500
	maxZipTotalBytes   = 32 << 20
	maxJSONNodes       = 2000
)

// SourceKind 的合法值
var validSourceKinds = map[string]bool{
	"ovpn": true, "zip": true, "csv": true, "json": true,
}

// Source 是一条自定义来源。
type Source struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Kind        string    `json:"kind"`
	CountryCode string    `json:"country_code,omitempty"`
	Country     string    `json:"country,omitempty"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"-"`
	HasPassword bool      `json:"has_password"`
	Enabled     bool      `json:"enabled"`
	LastFetch   time.Time `json:"last_fetch,omitempty"`
	LastCount   int       `json:"last_count"`
	LastError   string    `json:"last_error,omitempty"`
}

func sourcesPath(dir string) string { return filepath.Join(dir, "sources.json") }

// sourceStore 管来源的增删改查与落盘。
type sourceStore struct {
	mu      sync.RWMutex
	dir     string
	sources []*Source
	// passwords 单独记，避免 JSON 序列化时意外落盘明文
	passwords map[string]string
}

func newSourceStore(dir string) *sourceStore {
	st := &sourceStore{dir: dir, passwords: map[string]string{}}
	st.load()
	return st
}

// persistedSource 是落盘形态（密码单独存另一个文件）。
type persistedSource struct {
	Source
	Password string `json:"password,omitempty"`
}

func (st *sourceStore) load() {
	blob, err := os.ReadFile(sourcesPath(st.dir))
	if err != nil {
		return
	}
	var list []persistedSource
	if err := json.Unmarshal(blob, &list); err != nil {
		return
	}
	for _, p := range list {
		s := p.Source
		if p.Password != "" {
			st.passwords[s.ID] = p.Password
			s.HasPassword = true
		}
		s.Password = ""
		st.sources = append(st.sources, &s)
	}
}

func (st *sourceStore) save() error {
	st.mu.RLock()
	list := make([]persistedSource, 0, len(st.sources))
	for _, s := range st.sources {
		ps := persistedSource{Source: *s, Password: st.passwords[s.ID]}
		list = append(list, ps)
	}
	st.mu.RUnlock()
	blob, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := sourcesPath(st.dir) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, sourcesPath(st.dir))
}

// List 返回来源列表副本（密码不带出）。
func (st *sourceStore) List() []Source {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make([]Source, 0, len(st.sources))
	for _, s := range st.sources {
		c := *s
		c.Password = ""
		out = append(out, c)
	}
	return out
}

// Upsert 新增或更新一条来源。id 为空表示新增。
// password 为空表示保留旧密码；clearPassword=true 时删除旧密码。
func (st *sourceStore) Upsert(in Source, password string, clearPassword bool) (*Source, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("名称不能为空")
	}
	if !validSourceKinds[in.Kind] {
		return nil, fmt.Errorf("类型只支持 ovpn/zip/csv/json")
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("URL 必须是 https 地址")
	}
	if in.CountryCode != "" && len(in.CountryCode) != 2 {
		return nil, fmt.Errorf("国家代码须为 2 字母")
	}
	in.CountryCode = strings.ToUpper(in.CountryCode)

	st.mu.Lock()
	defer st.mu.Unlock()
	if in.ID == "" {
		if len(st.sources) >= maxCustomSources {
			return nil, fmt.Errorf("自定义来源最多 %d 个", maxCustomSources)
		}
		tok, err := randomToken(8)
		if err != nil {
			return nil, err
		}
		in.ID = tok
		in.Enabled = true
		s := in
		st.sources = append(st.sources, &s)
		if password != "" {
			st.passwords[s.ID] = password
			s.HasPassword = true
		}
		out := s
		out.Password = ""
		st.mu.Unlock()
		serr := st.save()
		st.mu.Lock()
		return &out, serr
	}
	for _, s := range st.sources {
		if s.ID == in.ID {
			s.Name, s.URL, s.Kind = in.Name, in.URL, in.Kind
			s.CountryCode, s.Country = in.CountryCode, in.Country
			s.Username = in.Username
			s.Enabled = in.Enabled
			if clearPassword {
				delete(st.passwords, s.ID)
				s.HasPassword = false
			} else if password != "" {
				st.passwords[s.ID] = password
				s.HasPassword = true
			}
			out := *s
			out.Password = ""
			st.mu.Unlock()
			serr := st.save()
			st.mu.Lock()
			return &out, serr
		}
	}
	return nil, fmt.Errorf("来源不存在")
}

// Delete 删除一条来源。停用/删除只影响后续候选，不中断已运行的出口。
func (st *sourceStore) Delete(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, s := range st.sources {
		if s.ID == id {
			st.sources = append(st.sources[:i], st.sources[i+1:]...)
			delete(st.passwords, id)
			return st.saveLocked()
		}
	}
	return fmt.Errorf("来源不存在")
}

func (st *sourceStore) saveLocked() error {
	list := make([]persistedSource, 0, len(st.sources))
	for _, s := range st.sources {
		list = append(list, persistedSource{Source: *s, Password: st.passwords[s.ID]})
	}
	blob, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := sourcesPath(st.dir) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, sourcesPath(st.dir))
}

// enabled 返回启用的来源（含密码副本，供抓取用）。
func (st *sourceStore) enabled() []persistedSource {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var out []persistedSource
	for _, s := range st.sources {
		if s.Enabled {
			out = append(out, persistedSource{Source: *s, Password: st.passwords[s.ID]})
		}
	}
	return out
}

// markResult 记录一次抓取结果。
func (st *sourceStore) markResult(id string, count int, errMsg string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.sources {
		if s.ID == id {
			s.LastFetch = time.Now()
			s.LastCount = count
			s.LastError = errMsg
			break
		}
	}
	_ = st.saveLocked()
}

// sourceHTTPClient 是来源抓取用的 HTTP 客户端：30 秒超时、最多 5 跳重定向。
func sourceHTTPClient() *http.Client {
	return &http.Client{
		Timeout: sourceFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxSourceRedirects {
				return fmt.Errorf("重定向过多")
			}
			return nil
		},
	}
}

// fetchSource 抓取一条来源并解析成节点列表。
func fetchSource(s persistedSource) ([]Node, error) {
	req, err := http.NewRequest(http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fanout-source-fetch")
	if s.Username != "" {
		req.SetBasicAuth(s.Username, s.Password)
	}
	resp, err := sourceHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("抓取失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := readBodyLimited(resp, maxSourceBytes)
	if err != nil {
		return nil, err
	}

	var nodes []Node
	switch s.Kind {
	case "ovpn":
		n, err := nodeFromOvpn(string(raw), s)
		if err != nil {
			return nil, err
		}
		nodes = []Node{n}
	case "zip":
		nodes, err = nodesFromZip(raw, s)
	case "csv":
		nodes, err = parseNodeCSV(string(raw))
	case "json":
		nodes, err = nodesFromJSON(raw, s)
	default:
		return nil, fmt.Errorf("未知类型 %s", s.Kind)
	}
	if err != nil {
		return nil, err
	}
	// 统一打标：来源名与国家覆盖
	for i := range nodes {
		nodes[i].Source = s.Name
		if s.CountryCode != "" {
			nodes[i].CountryCode = s.CountryCode
			if s.Country != "" {
				nodes[i].Country = s.Country
			}
		}
	}
	return nodes, nil
}

// nodeFromOvpn 把一份 ovpn 文本变成节点。hostname 取自配置里的 remote，
// 拿不到就用来源名，保证不为空。
func nodeFromOvpn(cfg string, s persistedSource) (Node, error) {
	if err := validateOvpnConfig(cfg); err != nil {
		return Node{}, fmt.Errorf("配置未通过安全校验: %w", err)
	}
	host := ovpnRemoteHost(cfg)
	if host == "" {
		host = s.Name
	}
	ip := host
	if pip := netParseIP(host); pip != "" {
		ip = pip
	}
	return Node{
		HostName:    host,
		IP:          ip,
		Country:     s.Country,
		CountryCode: s.CountryCode,
		Config:      cfg,
		Residential: true, // 用户自己的来源默认按家宽处理，不套用 VPN Gate 的机房判据
	}, nil
}

// ovpnRemoteHost 取配置里第一个 remote 的主机。
func ovpnRemoteHost(cfg string) string {
	for _, line := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.TrimSpace(stripOvpnComment(line)))
		if len(f) >= 2 && strings.EqualFold(strings.TrimLeft(f[0], "-"), "remote") {
			return f[1]
		}
	}
	return ""
}

// nodesFromZip 从 zip 包里提 .ovpn 文件（内存解，不落盘）。
func nodesFromZip(raw []byte, s persistedSource) ([]Node, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("zip 解析失败: %w", err)
	}
	var nodes []Node
	var total int64
	for _, f := range zr.File {
		if len(nodes) >= maxZipEntries {
			break
		}
		name := strings.ToLower(f.Name)
		if !strings.HasSuffix(name, ".ovpn") {
			continue
		}
		if f.UncompressedSize64 > maxSourceBytes {
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > maxZipTotalBytes {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		cfg, err := io.ReadAll(io.LimitReader(rc, maxSourceBytes+1))
		rc.Close()
		if err != nil || int64(len(cfg)) > maxSourceBytes {
			continue
		}
		n, err := nodeFromOvpn(string(cfg), s)
		if err != nil {
			continue // 单个配置不合格就跳过，不影响整包
		}
		// 用文件名当 hostname 更易区分
		if base := filepath.Base(f.Name); base != "" {
			n.HostName = strings.TrimSuffix(base, filepath.Ext(base))
		}
		nodes = append(nodes, n)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("zip 里没有可用的 .ovpn 配置")
	}
	return nodes, nil
}

// jsonSourceDoc 是 json 来源的格式说明。
const jsonSourceDoc = `{"nodes":[{"hostname":"us1.example.com","ip":"1.2.3.4","port":1194,"country_code":"US","operator":"Example ISP","config":"<ovpn 文本>","config_b64":"<base64>"}]}`

type jsonNodeEntry struct {
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	CountryCode string `json:"country_code"`
	Country     string `json:"country"`
	Operator    string `json:"operator"`
	Config      string `json:"config"`
	ConfigB64   string `json:"config_b64"`
}

// nodesFromJSON 解析配置清单。config 与 config_b64 二选一填。
func nodesFromJSON(raw []byte, s persistedSource) ([]Node, error) {
	var doc struct {
		Nodes []jsonNodeEntry `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}
	var nodes []Node
	for _, e := range doc.Nodes {
		if len(nodes) >= maxJSONNodes {
			break
		}
		cfg := e.Config
		if cfg == "" && e.ConfigB64 != "" {
			b, err := base64.StdEncoding.DecodeString(e.ConfigB64)
			if err != nil {
				continue
			}
			cfg = string(b)
		}
		if cfg == "" || e.Hostname == "" {
			continue
		}
		if err := validateOvpnConfig(cfg); err != nil {
			continue
		}
		ip := e.IP
		if ip == "" {
			ip = e.Hostname
		}
		nodes = append(nodes, Node{
			HostName:    e.Hostname,
			IP:          ip,
			Country:     e.Country,
			CountryCode: strings.ToUpper(e.CountryCode),
			Operator:    strings.TrimSpace(e.Operator),
			Config:      cfg,
			Residential: true,
		})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("JSON 里没有可用节点")
	}
	return nodes, nil
}

// apiSources 来源管理：GET 列表 / POST 新增或更新 / DELETE 删除。
func apiSources(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := m.Sources()
		if st == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "来源管理器未初始化"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, st.List())
		case http.MethodPost:
			var req struct {
				ID            string `json:"id"`
				Name          string `json:"name"`
				URL           string `json:"url"`
				Kind          string `json:"kind"`
				CountryCode   string `json:"country_code"`
				Country       string `json:"country"`
				Username      string `json:"username"`
				Password      string `json:"password"`
				ClearPassword bool   `json:"clear_password"`
				Enabled       *bool  `json:"enabled"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败: " + err.Error()})
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			s, err := st.Upsert(Source{
				ID: req.ID, Name: req.Name, URL: req.URL, Kind: req.Kind,
				CountryCode: req.CountryCode, Country: req.Country,
				Username: req.Username, Enabled: enabled,
			}, req.Password, req.ClearPassword)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, s)
		case http.MethodDelete:
			if err := st.Delete(r.URL.Query().Get("id")); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "已删除"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET/POST/DELETE"})
		}
	}
}

// apiSourcesRefresh 手动刷新自定义来源：?id= 只刷一条，不带刷全部启用的。
func apiSourcesRefresh(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只接受 POST"})
			return
		}
		st := m.Sources()
		if st == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "来源管理器未初始化"})
			return
		}
		id := r.URL.Query().Get("id")
		var total int
		var errs []string
		for _, s := range st.enabled() {
			if id != "" && s.ID != id {
				continue
			}
			nodes, err := fetchSource(s)
			if err != nil {
				st.markResult(s.ID, 0, firstLine(err.Error()))
				errs = append(errs, s.Name+": "+firstLine(err.Error()))
				continue
			}
			st.markResult(s.ID, len(nodes), "")
			total += len(nodes)
		}
		// 刷新完顺手把节点列表也更新了，界面立刻能看到新节点
		if _, err := m.RefreshNodes(); err != nil {
			errs = append(errs, "主源刷新失败: "+firstLine(err.Error()))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"nodes":  total,
			"errors": errs,
		})
	}
}

// netParseIP 小工具：是 IP 就原样返回，否则空串。
func netParseIP(s string) string {
	s = strings.TrimSpace(s)
	// 去掉可能带的端口
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}
