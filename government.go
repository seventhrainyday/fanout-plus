package main

import (
	"fmt"
	"net/url"
	"strings"
)

// 政府/公共机构候选分类。
//
// 先说清楚这是什么、不是什么：
//   - 是：按 hostname / Operator 里的关键词做的"疑似"启发式分类，
//     以及管理员自己声明的来源标记。用于在几千个节点里快速筛出一批
//     可能有机构背景的候选，省得人工一条条看。
//   - 不是：对节点真实所有权、访问授权、匿名性或稳定性的任何证明。
//     "疑似"标签不能证明这是政府服务器，更不能证明连上去合法。
//
// 界面展示时疑似项必须标注"疑似 · 未核验"，分类依据可查，
// 不得渲染成已证实的政府节点。

// GovClass 是机构分类。
type GovClass string

const (
	GovNone      GovClass = ""          // 无机构线索
	GovSuspected GovClass = "suspected" // 疑似：关键词命中，未核验
	GovDeclared  GovClass = "declared"  // 管理员声明：来源管理员标注并给出说明链接（链接内容未独立核验）
)

// GovFilter 是新建出口时的机构筛选模式。
const (
	GovFilterOff               = 0 // 不过滤
	GovFilterIncludeSuspected  = 1 // 政府/公共机构（含疑似）：declared + suspected
	GovFilterSuspectedOnly     = 2 // 仅疑似
	GovFilterDeclaredOnly      = 3 // 仅管理员声明
)

// govSuspectKeywords 是疑似机构关键词（小写匹配）。
// 覆盖政府、军队、警方、高校、公共事业几类。注意这是非常宽的网：
// 比如 "education" 会命中大量学校节点——这正是"疑似"的含义，
// 宁可多标、不可漏标，是否真有机构背景由用户自己判断。
var govSuspectKeywords = []string{
	// 政府
	"gov", "government", "ministry", "minister", "parliament", "congress",
	"senate", "assembly", "cabinet", "bureau", "agency", "authority",
	"municipal", "prefecture", "province", "county",
	"政府", "政务", "市政", "省府", "官厅",
	// 军队警方司法
	"military", "army", "navy", "airforce", "defense", "defence",
	"police", "sheriff", "court", "justice", "prison",
	"公安", "警察", "法院", "检察院", "司法", "军队",
	// 高校与科研
	"university", "college", "school", "campus", "academy", "institute",
	".edu", ".ac.", "edu.", "大学", "学院", "学校", "教育",
	// 公共事业
	"hospital", "museum", "library", "post",
	"医院", "卫生", "图书馆", "博物馆", "邮政",
}

// classifyGov 按 hostname 与 operator 做疑似分类，返回分类与依据。
// 关键词命中即标疑似，不做真实性判断。
func classifyGov(hostname, operator string) (GovClass, string) {
	hay := strings.ToLower(strings.TrimSpace(hostname)) + " " +
		strings.ToLower(strings.TrimSpace(operator))
	for _, kw := range govSuspectKeywords {
		if strings.Contains(hay, kw) {
			where := "hostname"
			if strings.Contains(strings.ToLower(operator), kw) {
				where = "operator"
			} else if !strings.Contains(strings.ToLower(hostname), kw) {
				where = "hostname/operator"
			}
			return GovSuspected, fmt.Sprintf("%s 含关键词 %q（未核验）", where, kw)
		}
	}
	return GovNone, ""
}

// govPass 判断一个节点是否通过指定模式的机构筛选。
func govPass(class GovClass, mode int) bool {
	switch mode {
	case GovFilterOff:
		return true
	case GovFilterIncludeSuspected:
		return class == GovSuspected || class == GovDeclared
	case GovFilterSuspectedOnly:
		return class == GovSuspected
	case GovFilterDeclaredOnly:
		return class == GovDeclared
	default:
		return true
	}
}

// validateGovURL 校验管理员声明的政府说明链接。
// 只校验格式：必须是 https，且 host 里含 gov（启发式）。
// 明确不做：拉取页面、核验内容、核验机构身份与真实授权。
// 通过校验不代表该来源真的获得政府授权。
func validateGovURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("声明授权来源必须提供说明链接")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("说明链接必须是 https 地址")
	}
	if !strings.Contains(strings.ToLower(u.Host), "gov") {
		return fmt.Errorf("说明链接 host 不含 gov，请确认是政府官方域名")
	}
	return nil
}

// govClassLabel 是界面展示用的分类文案。
func govClassLabel(c GovClass) string {
	switch c {
	case GovSuspected:
		return "疑似机构 · 未核验"
	case GovDeclared:
		return "管理员声明授权（链接未核验）"
	default:
		return ""
	}
}
