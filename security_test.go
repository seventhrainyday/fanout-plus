package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsCrossSitePOST(t *testing.T) {
	mkReq := func(origin, sfs string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://1.2.3.4:8899/login", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if sfs != "" {
			r.Header.Set("Sec-Fetch-Site", sfs)
		}
		return r
	}

	// 同源请求放行
	if isCrossSitePOST(mkReq("http://1.2.3.4:8899", "")) {
		t.Error("同源 Origin 被误判为跨站")
	}
	// 不带 Origin 的老客户端放行
	if isCrossSitePOST(mkReq("", "")) {
		t.Error("无 Origin 请求被误判为跨站")
	}
	// 跨站 Origin 拦截
	if !isCrossSitePOST(mkReq("http://evil.example.com", "")) {
		t.Error("跨站 Origin 未被拦截")
	}
	// Sec-Fetch-Site: cross-site 拦截（优先级高于 Origin）
	if !isCrossSitePOST(mkReq("http://1.2.3.4:8899", "cross-site")) {
		t.Error("Sec-Fetch-Site: cross-site 未被拦截")
	}
	// same-origin 的 Fetch Metadata 放行
	if isCrossSitePOST(mkReq("", "same-origin")) {
		t.Error("same-origin 被误判为跨站")
	}
	// GET 请求不受影响
	r := httptest.NewRequest(http.MethodGet, "http://1.2.3.4:8899/", nil)
	r.Header.Set("Origin", "http://evil.example.com")
	if isCrossSitePOST(r) {
		t.Error("GET 请求被误判")
	}
}

func TestBuildUDPRespHeaderDomain(t *testing.T) {
	domain := []byte("example.com")
	pkt := buildUDPRespHeader(atypDomain, domain, 53, []byte{1, 2, 3})
	// RSV(3) + atyp(1) + len(1) + domain(11) + port(2) + data(3)
	if len(pkt) != 3+1+1+len(domain)+2+3 {
		t.Fatalf("回包长度不对: %d", len(pkt))
	}
	if pkt[3] != atypDomain || pkt[4] != byte(len(domain)) {
		t.Errorf("域名回包缺长度字节: %v", pkt[:6])
	}
	if string(pkt[5:5+len(domain)]) != "example.com" {
		t.Errorf("域名内容不对: %v", pkt)
	}
	// IPv4 回包不受影响（无长度字节）
	pkt4 := buildUDPRespHeader(atypIPv4, []byte{1, 2, 3, 4}, 53, nil)
	if len(pkt4) != 3+1+4+2 {
		t.Errorf("IPv4 回包长度不对: %d", len(pkt4))
	}
}

func TestReadBodyLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := readBodyLimited(resp, 50); err == nil {
		t.Error("超限响应未被拦截")
	}

	resp2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	raw, err := readBodyLimited(resp2, 200)
	if err != nil || len(raw) != 100 {
		t.Errorf("正常响应被误杀: %v %d", err, len(raw))
	}
}
