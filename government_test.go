package main

import (
	"strings"
	"testing"
)

func TestClassifyGov(t *testing.T) {
	cases := []struct {
		host, op string
		want     GovClass
	}{
		{"vpn-gov-01.example.com", "", GovSuspected},
		{"public-vpn-123", "University of Tokyo", GovSuspected},
		{"vpn1", "Ministry of Education", GovSuspected},
		{"myhome-isp", "Chunghwa Telecom", GovNone},
		{"vpn1", "", GovNone},
		{"vpn-beijing-gov", "China Unicom", GovSuspected},
		{"node1", "市政网络中心", GovSuspected},
	}
	for _, c := range cases {
		got, reason := classifyGov(c.host, c.op)
		if got != c.want {
			t.Errorf("classifyGov(%q,%q)=%q，想要 %q", c.host, c.op, got, c.want)
		}
		if got == GovSuspected && reason == "" {
			t.Errorf("疑似项应当给出依据: %q %q", c.host, c.op)
		}
		if got == GovNone && reason != "" {
			t.Errorf("无分类不应当有依据: %q", reason)
		}
	}
}

func TestGovPass(t *testing.T) {
	// 不过滤全过
	for _, c := range []GovClass{GovNone, GovSuspected, GovDeclared} {
		if !govPass(c, GovFilterOff) {
			t.Errorf("不过滤时 %q 应当通过", c)
		}
	}
	if govPass(GovNone, GovFilterIncludeSuspected) {
		t.Error("含疑似模式下无分类不应当通过")
	}
	if !govPass(GovSuspected, GovFilterIncludeSuspected) || !govPass(GovDeclared, GovFilterIncludeSuspected) {
		t.Error("含疑似模式下疑似/声明应当通过")
	}
	if !govPass(GovSuspected, GovFilterSuspectedOnly) || govPass(GovDeclared, GovFilterSuspectedOnly) {
		t.Error("仅疑似模式逻辑不对")
	}
	if !govPass(GovDeclared, GovFilterDeclaredOnly) || govPass(GovSuspected, GovFilterDeclaredOnly) {
		t.Error("仅声明模式逻辑不对")
	}
}

func TestValidateGovURL(t *testing.T) {
	if err := validateGovURL("https://www.gov.example/notice.html"); err != nil {
		t.Errorf("合法 gov 链接被拒绝: %v", err)
	}
	for _, bad := range []string{
		"",
		"http://www.gov.example/a",   // 非 https
		"https://example.com/gov/a",  // host 不含 gov
		"not-a-url",
	} {
		if err := validateGovURL(bad); err == nil {
			t.Errorf("非法链接应当被拒绝: %q", bad)
		}
	}
}

func TestGovClassLabel(t *testing.T) {
	if l := govClassLabel(GovSuspected); l == "" {
		t.Error("疑似应当有展示文案")
	} else if !strings.Contains(l, "未核验") {
		// 文案必须带"未核验"，不能渲染成实证
		t.Errorf("疑似文案缺警示: %q", l)
	}
	if govClassLabel(GovNone) != "" {
		t.Error("无分类不应当有文案")
	}
}

// 机构筛选作用于挑节点
func TestPickNodesGovFilter(t *testing.T) {
	useTempSettings(t)
	m := NewManager(10, t.TempDir())
	m.nodes = []Node{
		{HostName: "gov1", CountryCode: "JP", SpeedMbps: 100, Residential: true, GovClass: GovSuspected, GovReason: "x"},
		{HostName: "home1", CountryCode: "JP", SpeedMbps: 90, Residential: true},
		{HostName: "decl1", CountryCode: "JP", SpeedMbps: 80, Residential: true, GovClass: GovDeclared},
	}
	// 仅疑似：只拿到 gov1
	picks, err := m.pickNodes("JP", 5, nil, GovFilterSuspectedOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 1 || picks[0].HostName != "gov1" {
		t.Errorf("仅疑似筛选不对: %+v", picks)
	}
	// 含疑似：gov1 + decl1
	picks, err = m.pickNodes("JP", 5, nil, GovFilterIncludeSuspected)
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 2 {
		t.Errorf("含疑似筛选不对: %+v", picks)
	}
	// 仅声明：decl1
	picks, err = m.pickNodes("JP", 5, nil, GovFilterDeclaredOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 1 || picks[0].HostName != "decl1" {
		t.Errorf("仅声明筛选不对: %+v", picks)
	}
}

// 声明来源的 URL 校验接入 Upsert
func TestSourceGovDeclared(t *testing.T) {
	st := newSourceStore(t.TempDir())
	// 声明但链接不合格
	if _, err := st.Upsert(Source{
		Name: "g1", URL: "https://example.com/a.ovpn", Kind: "ovpn",
		GovDeclared: true, GovURL: "https://example.com/notice",
	}, "", false); err == nil {
		t.Error("host 不含 gov 的说明链接应当被拒绝")
	}
	// 合格
	s, err := st.Upsert(Source{
		Name: "g1", URL: "https://example.com/a.ovpn", Kind: "ovpn",
		GovDeclared: true, GovURL: "https://www.gov.example/notice",
	}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.GovDeclared || s.GovURL == "" {
		t.Error("声明标记没存上")
	}
	// 取消声明时清空 URL
	s2, err := st.Upsert(Source{
		ID: s.ID, Name: "g1", URL: "https://example.com/a.ovpn", Kind: "ovpn",
		GovDeclared: false,
	}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if s2.GovDeclared || s2.GovURL != "" {
		t.Error("取消声明后 URL 应当清空")
	}
}
