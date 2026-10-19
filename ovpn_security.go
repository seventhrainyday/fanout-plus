package main

import (
	"fmt"
	"strings"
)

// OpenVPN 配置安全校验。
//
// 背景：节点配置来自公网来源（VPN Gate 等第三方），最终由 root 身份的
// openvpn 进程解析。配置里的 up/down 脚本、plugin、嵌套 include 等指令
// 一旦被利用，就是直接的本地提权向量。上游 fanout 对配置文本没有任何
// 校验，这里做白名单式检查：只放行已知无害的指令，危险的一律拒绝。
//
// 校验通过不代表配置"可信"，只代表它调不动 root 进程去执行额外代码。
// 真正的可用性仍由后续的隧道拨号与出口 IP 探测决定。

// maxOvpnConfigSize 是单份配置的上限。VPN Gate 的 inline 配置通常几 KB，
// 128KB 足够覆盖正常情况，又能挡住畸形/恶意大文本。
const maxOvpnConfigSize = 128 * 1024

// ovpnBlockedDirectives 是禁止出现在配置里的指令（小写）。
// 分类：
//   - 脚本执行：up/down/route-up/route-pre-down/ipchange/tls-verify/... 全部能跑外部命令
//   - 模块加载：plugin
//   - 配置嵌套：config/include（引入路径不可控的文件）
//   - 进程行为：script-security（我们在命令行强制，配置里不许再写）、
//     daemon/chroot/user/group（进程身份与形态由我们决定）、
//     management/log/status（管理接口与日志路径由我们决定）
//   - 环境变量：setenv（可被用来影响插件与脚本行为）
var ovpnBlockedDirectives = map[string]bool{
	"up": true, "down": true,
	"route-up": true, "route-pre-down": true,
	"ipchange": true, "tls-verify": true,
	"auth-user-pass-verify": true,
	"client-connect": true, "client-disconnect": true,
	"learn-address": true,
	"plugin": true, "plugins": true,
	"script-security": true,
	"setenv":          true,
	"setenv-safe":     true,
	"config":          true,
	"include":         true,
	"management":      true,
	"management-hold": true,
	"log":             true,
	"log-append":      true,
	"status":          true,
	"status-version":  true,
	"daemon":          true,
	"chroot":          true,
	"user":            true,
	"group":           true,
	"cd":              true,
	"writepid":        true,
	"nice":            true,
}

// ovpnAllowedBlocks 是允许的 inline 块（小写）。
// ca/cert/key/tls-auth/tls-crypt(-v2) 是 VPN Gate  inline 配置的常规内容；
// connection 是多 remote 写法，块内指令同样逐条校验，不许嵌套。
var ovpnAllowedBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true,
	"tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true,
	"connection": true,
}

// ovpnFileRefDirectives 是"带文件路径参数"的指令。
// 公网来源的配置应当全部 inline；一旦出现文件引用，路径完全不可控
// （可指向 /etc/shadow 等敏感文件，或配合 symlink 做文章），一律拒绝。
var ovpnFileRefDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true,
	"tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "dh": true, "crl-verify": true,
	"auth-user-pass": true, // 裸写（无参数）允许，带路径拒绝
	"http-proxy":          true, // http-proxy 的第二个参数是认证文件
	"http-proxy-userpass": true,
	"socks-proxy": true,
}

// validateOvpnConfig 校验一份 OpenVPN 客户端配置文本，不通过返回错误原因。
func validateOvpnConfig(cfg string) error {
	if len(cfg) > maxOvpnConfigSize {
		return fmt.Errorf("配置过大（%d 字节，上限 %d）", len(cfg), maxOvpnConfigSize)
	}
	if strings.TrimSpace(cfg) == "" {
		return fmt.Errorf("配置为空")
	}

	var (
		inBlock    string // 当前所在的 inline 块名，空表示不在块内
		inConn     bool   // 是否在 <connection> 块内：块内指令同样逐条校验
		seenRemote bool
	)

	for i, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(stripOvpnComment(raw))
		if line == "" {
			continue
		}

		// inline 块的起止行
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if inBlock != "" {
				return fmt.Errorf("第 %d 行：块 <%s> 内又开了 <%s>，不允许嵌套", i+1, inBlock, name)
			}
			if !ovpnAllowedBlocks[name] {
				return fmt.Errorf("第 %d 行：不允许的 inline 块 <%s>", i+1, name)
			}
			inBlock = name
			inConn = name == "connection"
			continue
		}
		if strings.HasPrefix(line, "</") && strings.HasSuffix(line, ">") {
			name := strings.ToLower(strings.TrimSpace(line[2 : len(line)-1]))
			if inBlock == "" {
				return fmt.Errorf("第 %d 行：</%s> 没有对应的开始标记", i+1, name)
			}
			if name != inBlock {
				return fmt.Errorf("第 %d 行：块 <%s> 用 </%s> 收尾，对不上", i+1, inBlock, name)
			}
			inBlock, inConn = "", false
			continue
		}
		if inBlock != "" && !inConn {
			continue // 证书类块体内容（base64 等）不逐行解释
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimLeft(fields[0], "-"))

		if ovpnBlockedDirectives[directive] {
			return fmt.Errorf("第 %d 行：不允许的指令 %q", i+1, fields[0])
		}
		if directive == "remote" {
			seenRemote = true
		}
		// 文件引用检查：这些指令一旦带了像路径的参数就拒绝。
		// http-proxy 的前两个参数是代理主机与端口，只从第三个（认证文件）起查。
		if ovpnFileRefDirectives[directive] && len(fields) > 1 {
			args := fields[1:]
			if directive == "http-proxy" && len(args) > 2 {
				args = args[2:]
			} else if directive == "http-proxy" {
				args = nil
			}
			for _, arg := range args {
				if looksLikePath(arg) {
					return fmt.Errorf("第 %d 行：指令 %q 不允许引用外部文件 %q，配置必须全部 inline", i+1, fields[0], arg)
				}
			}
		}
	}

	if inBlock != "" {
		return fmt.Errorf("块 <%s> 没有收尾标记", inBlock)
	}
	if !seenRemote {
		return fmt.Errorf("配置里没有 remote，无法拨号")
	}
	return nil
}

// stripOvpnComment 去掉行尾注释。OpenVPN 用 # 或 ; 开头表示注释，
// 行内注释只认前面有空白分隔的 # / ;，避免误伤密码里的符号。
func stripOvpnComment(line string) string {
	// 先找 # / ; 注释符，要求它前面是行首或空白
	for i := 0; i < len(line); i++ {
		if line[i] == '#' || line[i] == ';' {
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

// looksLikePath 判断一个参数像不像文件路径。
func looksLikePath(s string) bool {
	if s == "" {
		return false
	}
	// 绝对路径、家目录、Windows 盘符、含 / 的相对路径都算
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") {
		return true
	}
	if len(s) > 2 && s[1] == ':' {
		return true
	}
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return true
	}
	// 纯文件名但带常见证书/密钥后缀的也算（ca.crt 这类）
	lower := strings.ToLower(s)
	for _, ext := range []string{".crt", ".pem", ".key", ".p12", ".pfx", ".ovpn", ".conf", ".txt"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
