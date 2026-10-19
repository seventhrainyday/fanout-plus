package main

import (
	"path/filepath"
	"testing"
	"time"
)

// useTempSettings 把 WebSettings 指向临时目录，测试改开关不污染真实配置。
func useTempSettings(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	webSettingsMu.Lock()
	oldPath, oldCur := webSettingsPath, webSettingsCur
	webSettingsPath = filepath.Join(dir, "settings.json")
	webSettingsCur = WebSettings{}
	webSettingsMu.Unlock()
	t.Cleanup(func() {
		webSettingsMu.Lock()
		webSettingsPath, webSettingsCur = oldPath, oldCur
		webSettingsMu.Unlock()
	})
}

// 运营商多样性：同国多出口优先不同运营商
func TestCarrierDiversePick(t *testing.T) {
	useTempSettings(t)
	m := NewManager(10, t.TempDir())
	m.nodes = []Node{
		{HostName: "a1", CountryCode: "JP", Operator: "ISP-A", SpeedMbps: 100, Residential: true},
		{HostName: "a2", CountryCode: "JP", Operator: "ISP-A", SpeedMbps: 90, Residential: true},
		{HostName: "b1", CountryCode: "JP", Operator: "ISP-B", SpeedMbps: 80, Residential: true},
		{HostName: "c1", CountryCode: "JP", Operator: "", SpeedMbps: 70, Residential: true},
	}
	// 开关默认开
	picks, err := m.pickNodes("JP", 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 3 {
		t.Fatalf("应当挑出 3 个，实际 %d", len(picks))
	}
	ops := map[string]bool{}
	for _, p := range picks {
		ops[normOperator(p.Operator)] = true
	}
	// a1(ISP-A) b1(ISP-B) c1(空) —— 三个不同运营商，不该出现 a2
	for _, p := range picks {
		if p.HostName == "a2" {
			t.Errorf("同运营商重复被选中: %+v", picks)
		}
	}
	// 关掉开关后按速度顺序拿
	if err := setCarrierDiverse(false); err != nil {
		t.Fatal(err)
	}
	defer setCarrierDiverse(true)
	picks2, err := m.pickNodes("JP", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if picks2[0].HostName != "a1" || picks2[1].HostName != "a2" {
		t.Errorf("关闭多样性后应按速度拿 a1,a2，实际 %+v", picks2)
	}
}

// 订阅配额注入新客户端
func TestNewClientEntryQuota(t *testing.T) {
	useTempSettings(t)
	// 先清零
	if err := setSubQuota(0, 0); err != nil {
		t.Fatal(err)
	}
	c := newClientEntry("vless", "t@example.com")
	if c["totalGB"] != 0 || c["expiryTime"] != 0 {
		t.Errorf("未配额时应为 0: %+v", c)
	}
	// 配 10GB / 30 天
	if err := setSubQuota(10, 30); err != nil {
		t.Fatal(err)
	}
	defer setSubQuota(0, 0)
	c2 := newClientEntry("vless", "t2@example.com")
	if c2["totalGB"] != int64(10*1024*1024*1024) {
		t.Errorf("totalGB 不对: %v", c2["totalGB"])
	}
	exp, ok := c2["expiryTime"].(int64)
	if !ok || exp <= time.Now().UnixMilli() {
		t.Errorf("expiryTime 不对: %v", c2["expiryTime"])
	}
	// 大约 30 天后（允许 1 分钟误差）
	want := time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	if exp < want-60000 || exp > want+60000 {
		t.Errorf("expiryTime 偏差太大: %d vs %d", exp, want)
	}
	// trojan 走 password 字段
	c3 := newClientEntry("trojan", "t3@example.com")
	if _, ok := c3["password"]; !ok {
		t.Error("trojan 客户端应有 password")
	}
	if c3["totalGB"] != int64(10*1024*1024*1024) {
		t.Error("trojan 客户端也应带配额")
	}
	// 负值拒绝
	if err := setSubQuota(-1, 0); err == nil {
		t.Error("负流量应当被拒绝")
	}
}

// Operator 字段从 CSV 解析
func TestParseNodeCSVOperator(t *testing.T) {
	body := "HostName,IP,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Operator,OpenVPN_ConfigData_Base64\n" +
		"vpn1,1.2.3.4,10,1000000,Japan,JP,5,Test ISP," +
		"Y2xpZW50CmRldiB0dW4KcHJvdG8gdWRwCnJlbW90ZSAxLjIuMy40IDExOTQKPGNhPkFCQzwvY2E+\n"
	nodes, err := parseNodeCSV(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Operator != "Test ISP" {
		t.Errorf("Operator 没解析出来: %+v", nodes)
	}
}

// 订阅配额设置的读写
func TestSubQuotaValidation(t *testing.T) {
	useTempSettings(t)
	defer setSubQuota(0, 0)
	if err := setSubQuota(5.5, 7); err != nil {
		t.Fatal(err)
	}
	g, d := subQuota()
	if g != 5.5 || d != 7 {
		t.Errorf("读写不对: %v %v", g, d)
	}
}

