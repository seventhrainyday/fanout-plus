package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testOvpnCfg = `client
dev tun
proto udp
remote 9.9.9.9 1194
resolv-retry infinite
nobind
<ca>
CERTDATA
</ca>
`

func TestSourceUpsertValidation(t *testing.T) {
	st := newSourceStore(t.TempDir())
	// 非 https 拒绝
	if _, err := st.Upsert(Source{Name: "x", URL: "http://example.com/a.ovpn", Kind: "ovpn"}, "", false); err == nil {
		t.Error("http URL 应当被拒绝")
	}
	// 非法类型拒绝
	if _, err := st.Upsert(Source{Name: "x", URL: "https://example.com/a.ovpn", Kind: "rar"}, "", false); err == nil {
		t.Error("非法类型应当被拒绝")
	}
	// 空名拒绝
	if _, err := st.Upsert(Source{Name: "", URL: "https://example.com/a.ovpn", Kind: "ovpn"}, "", false); err == nil {
		t.Error("空名称应当被拒绝")
	}
	// 正常新增
	s, err := st.Upsert(Source{Name: "test", URL: "https://example.com/a.ovpn", Kind: "ovpn", CountryCode: "us"}, "secret", false)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID == "" || !s.HasPassword {
		t.Error("新增来源应当有 ID 并标记有密码")
	}
	if s.Password != "" {
		t.Error("列表返回不应带出密码明文")
	}
	// 空密码编辑保留旧密码
	s2, err := st.Upsert(Source{ID: s.ID, Name: "test2", URL: "https://example.com/b.ovpn", Kind: "ovpn"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.HasPassword {
		t.Error("空密码编辑应当保留旧密码")
	}
	// clearPassword 删除
	s3, err := st.Upsert(Source{ID: s.ID, Name: "test2", URL: "https://example.com/b.ovpn", Kind: "ovpn"}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if s3.HasPassword {
		t.Error("clearPassword 后不应再有密码")
	}
	// 落盘再读，密码还在
	st2 := newSourceStore(st.dir)
	list := st2.List()
	if len(list) != 1 || list[0].Name != "test2" {
		t.Errorf("落盘重读失败: %+v", list)
	}
}

func TestSourceMaxCount(t *testing.T) {
	st := newSourceStore(t.TempDir())
	for i := 0; i < maxCustomSources; i++ {
		if _, err := st.Upsert(Source{Name: "s", URL: "https://example.com/a.ovpn", Kind: "ovpn"}, "", false); err != nil {
			t.Fatalf("第 %d 个失败: %v", i, err)
		}
	}
	if _, err := st.Upsert(Source{Name: "overflow", URL: "https://example.com/a.ovpn", Kind: "ovpn"}, "", false); err == nil {
		t.Error("超过 20 个应当被拒绝")
	}
}

func TestFetchSourceOvpn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(testOvpnCfg))
	}))
	defer srv.Close()
	// httptest 是 http，fetchSource 要求调用方传 https；
	// 这里直接测解析路径：用 Upsert 校验挡 http，fetch 走本地函数需要 https。
	// 改为测 nodeFromOvpn 与 URL 校验两条线。
	n, err := nodeFromOvpn(testOvpnCfg, persistedSource{Source: Source{Name: "t", CountryCode: "US", Country: "美国"}})
	if err != nil {
		t.Fatal(err)
	}
	if n.HostName != "9.9.9.9" || n.CountryCode != "US" {
		t.Errorf("解析不对: %+v", n)
	}
	// 恶意配置被拦
	bad := testOvpnCfg + "up /tmp/x.sh\n"
	if _, err := nodeFromOvpn(bad, persistedSource{}); err == nil {
		t.Error("恶意配置应当被拦截")
	}
	_ = srv
}

func TestFetchSourceZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"a.ovpn", "b.ovpn", "readme.txt"} {
		fw, _ := zw.Create(name)
		content := testOvpnCfg
		if strings.HasSuffix(name, ".txt") {
			content = "hello"
		}
		_, _ = fw.Write([]byte(content))
	}
	_ = zw.Close()

	nodes, err := nodesFromZip(buf.Bytes(), persistedSource{Source: Source{Name: "ziptest"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Errorf("应当解析出 2 个节点，实际 %d (%+v)", len(nodes), nodes)
	}
	// 来源名由 fetchSource 统一打标，这里验证 hostname 取自文件名
	names := map[string]bool{}
	for _, n := range nodes {
		names[n.HostName] = true
	}
	if !names["a"] || !names["b"] {
		t.Errorf("hostname 应取自文件名: %+v", nodes)
	}
}

func TestFetchSourceJSON(t *testing.T) {
	doc := `{"nodes":[
		{"hostname":"h1","ip":"1.1.1.1","country_code":"us","operator":"ISP-A","config_b64":"` +
		base64.StdEncoding.EncodeToString([]byte(testOvpnCfg)) + `"},
		{"hostname":"h2","config":"` + strings.ReplaceAll(testOvpnCfg, "\n", "\\n") + `"},
		{"hostname":"","config":"x"},
		{"hostname":"bad","config":"up /tmp/x.sh\nremote 1.1.1.1 1194\n"}
	]}`
	nodes, err := nodesFromJSON([]byte(doc), persistedSource{Source: Source{Name: "jsontest"}})
	if err != nil {
		t.Fatal(err)
	}
	// h1、h2 通过；空 hostname 跳过；恶意配置跳过
	if len(nodes) != 2 {
		t.Fatalf("应当解析出 2 个节点，实际 %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Operator != "ISP-A" || nodes[0].IP != "1.1.1.1" {
		t.Errorf("字段不对: %+v", nodes[0])
	}
}

func TestMergeNodeLists(t *testing.T) {
	main := []Node{{HostName: "a"}, {HostName: "b"}}
	custom := []Node{{HostName: "b"}, {HostName: "c", Source: "s1"}}
	out := mergeNodeLists(main, custom)
	if len(out) != 3 {
		t.Fatalf("去重合并应当 3 个，实际 %d", len(out))
	}
	if out[2].Source != "s1" {
		t.Error("自定义节点来源标记丢失")
	}
}
