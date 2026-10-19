package main

import (
	"fmt"
	"io"
	"net/http"
)

// HTTP 响应体读取上限：防止恶意/失控的上游返回超大响应把内存撑爆。
// VPN Gate 的节点 CSV 也就 1~2MB，x-ui API 响应都是 KB 级，
// 这里的上限留得足够宽松，正常情况碰不到。
const (
	maxNodeListBytes = 16 << 20 // 节点列表类：16MB
	maxAPIRespBytes  = 4 << 20  // 面板 API 类：4MB
)

// readBodyLimited 限量读取 HTTP 响应体，超限返回错误。
func readBodyLimited(resp *http.Response, maxBytes int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("响应体超过 %d 字节上限", maxBytes)
	}
	return raw, nil
}
