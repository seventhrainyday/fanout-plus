package main

import (
	"strings"
	"testing"
)

// 典型的 VPN Gate inline 配置：应当通过
const validOvpnSample = `client
dev tun
proto udp
remote 1.2.3.4 1195
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth-user-pass
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
abcd
-----END OpenVPN Static key V1-----
</tls-auth>
key-direction 1
`

func TestValidateOvpnValid(t *testing.T) {
	if err := validateOvpnConfig(validOvpnSample); err != nil {
		t.Fatalf("合法配置被拒绝: %v", err)
	}
}

func TestValidateOvpnBlocked(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"up 脚本", "up /tmp/evil.sh"},
		{"down 脚本", "down /tmp/evil.sh"},
		{"route-up", "route-up /tmp/x.sh"},
		{"plugin", "plugin /usr/lib/openvpn/plugins/openvpn-plugin-auth-pam.so login"},
		{"script-security", "script-security 2"},
		{"setenv", "setenv FOO bar"},
		{"config 嵌套", "config /tmp/other.ovpn"},
		{"management", "management 127.0.0.1 6001"},
		{"tls-verify", "tls-verify /tmp/v.sh"},
		{"chroot", "chroot /tmp/jail"},
		{"user", "user nobody"},
		{"log 路径", "log /tmp/openvpn.log"},
	}
	for _, c := range cases {
		cfg := "client\ndev tun\nproto udp\nremote 1.2.3.4 1195\n" + c.line + "\n"
		if err := validateOvpnConfig(cfg); err == nil {
			t.Errorf("%s: 危险指令未被拦截", c.name)
		}
	}
}

func TestValidateOvpnBlocks(t *testing.T) {
	// 未知 inline 块拒绝
	cfg := "client\nremote 1.2.3.4 1195\n<evil>\nabc\n</evil>\n"
	if err := validateOvpnConfig(cfg); err == nil {
		t.Error("未知 inline 块未被拦截")
	}
	// 块未收尾拒绝
	cfg = "client\nremote 1.2.3.4 1195\n<ca>\nabc\n"
	if err := validateOvpnConfig(cfg); err == nil {
		t.Error("未收尾的块未被拦截")
	}
	// connection 块内同样校验指令
	cfg = "client\nremote 1.2.3.4 1195\n<connection>\nup /tmp/x.sh\n</connection>\n"
	if err := validateOvpnConfig(cfg); err == nil {
		t.Error("connection 块内的危险指令未被拦截")
	}
	// 合法的 connection 块通过
	cfg = "client\n<connection>\nremote 1.2.3.4 1195\nproto udp\n</connection>\n"
	if err := validateOvpnConfig(cfg); err != nil {
		t.Errorf("合法 connection 块被拒绝: %v", err)
	}
}

func TestValidateOvpnFileRef(t *testing.T) {
	for _, line := range []string{
		"ca /etc/openvpn/ca.crt",
		"cert ca.crt",
		"tls-auth ta.key 1",
		"auth-user-pass /tmp/pass.txt",
	} {
		cfg := "client\ndev tun\nremote 1.2.3.4 1195\n" + line + "\n"
		if err := validateOvpnConfig(cfg); err == nil {
			t.Errorf("文件引用未被拦截: %s", line)
		}
	}
	// 裸 auth-user-pass 允许（凭据走命令行传入）
	cfg := "client\ndev tun\nremote 1.2.3.4 1195\nauth-user-pass\n"
	if err := validateOvpnConfig(cfg); err != nil {
		t.Errorf("裸 auth-user-pass 被误杀: %v", err)
	}
}

func TestValidateOvpnBasics(t *testing.T) {
	if err := validateOvpnConfig(""); err == nil {
		t.Error("空配置未被拦截")
	}
	if err := validateOvpnConfig(strings.Repeat("x", maxOvpnConfigSize+1)); err == nil {
		t.Error("超大配置未被拦截")
	}
	// 没有 remote 的配置拒绝
	if err := validateOvpnConfig("client\ndev tun\nproto udp\n"); err == nil {
		t.Error("无 remote 的配置未被拦截")
	}
	// 注释行不干扰
	cfg := "# 这是注释\n; 也是注释\nclient # 行尾注释\nremote 1.2.3.4 1195 ; 行尾注释\n"
	if err := validateOvpnConfig(cfg); err != nil {
		t.Errorf("注释处理有误: %v", err)
	}
}
