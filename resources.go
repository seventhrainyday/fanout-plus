package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 资源保护：新建出口的准入检查。
//
// 背景：每条隧道都是一个 openvpn 进程 + 一套 netns + iptables 规则，
// 开几十条之后 CPU/内存会吃紧。在小内存 VPS 上无节制新建会把机器拖死，
// 甚至把面板自己也卡到连不上。本模块做两件事：
//
//  1. 后台每秒采样 CPU 与内存（识别 cgroup v1/v2 限制，容器里不看错数）；
//  2. 新建出口前做准入检查：CPU 或内存达到阈值就暂停新建，并给出原因。
//
// 这是"采样后的新增限制"，不是操作系统硬限额：已有连接的负载增长、
// 进程启动的短时峰值仍可能让占用超过阈值，不能承诺始终不超过阈值。

const (
	// 默认阈值：CPU 或内存任一达到 80% 就暂停新建
	defaultResourceThreshold = 80
	minResourceThreshold     = 50
	maxResourceThreshold     = 95
	// 采样间隔与样本过期时间
	resourceSampleInterval = time.Second
	resourceSampleTTL      = 5 * time.Second
)

// ResourceSample 是一次资源采样。
type ResourceSample struct {
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float64   `json:"mem_percent"`
	SwapPercent float64  `json:"swap_percent"`
	Updated    time.Time `json:"updated"`
	Err        string    `json:"err,omitempty"`
}

// ResourceGuard 是资源保护开关与阈值。
type ResourceGuard struct {
	mu        sync.RWMutex
	enabled   bool
	threshold int

	sampleMu sync.RWMutex
	sample   ResourceSample

	stopCh chan struct{}
	once   sync.Once
}

// NewResourceGuard 建一个资源保护器，enabled 决定是否启用，threshold 为 0 时用默认值。
func NewResourceGuard(enabled bool, threshold int) *ResourceGuard {
	if threshold == 0 {
		threshold = defaultResourceThreshold
	}
	return &ResourceGuard{enabled: enabled, threshold: threshold}
}

// Start 启动后台采样。重复调用只生效一次。
func (g *ResourceGuard) Start() {
	g.once.Do(func() {
		g.stopCh = make(chan struct{})
		go g.loop()
	})
}

// Stop 停止后台采样。
func (g *ResourceGuard) Stop() {
	if g.stopCh != nil {
		close(g.stopCh)
	}
}

func (g *ResourceGuard) loop() {
	t := time.NewTicker(resourceSampleInterval)
	defer t.Stop()
	var prevCPU cpuTimes
	first := true
	for {
		select {
		case <-g.stopCh:
			return
		case <-t.C:
			s := ResourceSample{Updated: time.Now()}
			cur, err := readCPUTimes()
			if err != nil {
				s.Err = fmt.Sprintf("读 CPU 失败: %v", err)
			} else if !first {
				s.CPUPercent = cpuPercent(prevCPU, cur)
			} else {
				first = false
			}
			prevCPU = cur
			if merr := fillMemSample(&s); merr != nil && s.Err == "" {
				s.Err = merr.Error()
			}
			g.sampleMu.Lock()
			g.sample = s
			g.sampleMu.Unlock()
		}
	}
}

// Sample 返回最近一次采样（副本）。
func (g *ResourceGuard) Sample() ResourceSample {
	g.sampleMu.RLock()
	defer g.sampleMu.RUnlock()
	return g.sample
}

// Config 返回当前开关与阈值。
func (g *ResourceGuard) Config() (bool, int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.enabled, g.threshold
}

// SetConfig 改开关与阈值。threshold 传 0 表示不动，传 -1 表示关闭保护。
// 范围限制在 50~95，之外的拒绝。
func (g *ResourceGuard) SetConfig(enabled *bool, threshold int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if threshold != 0 {
		if threshold < minResourceThreshold || threshold > maxResourceThreshold {
			return fmt.Errorf("阈值须在 %d~%d 之间", minResourceThreshold, maxResourceThreshold)
		}
		g.threshold = threshold
	}
	if enabled != nil {
		g.enabled = *enabled
	}
	return nil
}

// AdmissionCheck 做新建出口的准入检查。
// 返回 ok=false 时 reason 说明原因，界面直接展示给用户。
//
// 保护开启时 fail-closed：读不到资源、CPU 还没完成首轮采样、
// 样本超过 5 秒没更新，都视为"状态未知"，暂停新增而不是放行。
// 保护关闭时永远放行（调用方仍要自己检查槽位）。
func (g *ResourceGuard) AdmissionCheck() (ok bool, reason string) {
	g.mu.RLock()
	enabled, threshold := g.enabled, g.threshold
	g.mu.RUnlock()
	if !enabled {
		return true, ""
	}
	s := g.Sample()
	if s.Err != "" {
		return false, "资源采样失败，暂停新建："+s.Err
	}
	if time.Since(s.Updated) > resourceSampleTTL {
		return false, "资源采样过期，暂停新建"
	}
	// 首轮采样还没有 CPU 差值，视为未知
	if s.Updated.IsZero() {
		return false, "等待首次资源采样，暂停新建"
	}
	if s.CPUPercent >= float64(threshold) {
		return false, fmt.Sprintf("CPU %.0f%% 达到阈值 %d%%，暂停新建", s.CPUPercent, threshold)
	}
	if s.MemPercent >= float64(threshold) {
		return false, fmt.Sprintf("内存 %.0f%% 达到阈值 %d%%，暂停新建", s.MemPercent, threshold)
	}
	return true, ""
}

// cpuTimes 是 /proc/stat 第一行的累计值。
type cpuTimes struct {
	idle  uint64
	total uint64
}

func readCPUTimes() (cpuTimes, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return cpuTimes{}, fmt.Errorf("/proc/stat 为空")
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("/proc/stat 格式异常")
	}
	var vals []uint64
	for _, fd := range fields[1:] {
		v, err := strconv.ParseUint(fd, 10, 64)
		if err != nil {
			return cpuTimes{}, err
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	// idle + iowait 算空闲
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuTimes{idle: idle, total: total}, nil
}

func cpuPercent(prev, cur cpuTimes) float64 {
	dTotal := cur.total - prev.total
	dIdle := cur.idle - prev.idle
	if dTotal == 0 || dIdle > dTotal {
		return 0
	}
	return 100 * float64(dTotal-dIdle) / float64(dTotal)
}

// fillMemSample 填充内存/swap 占用率，优先识别 cgroup 限制。
func fillMemSample(s *ResourceSample) error {
	total, avail, err := hostMem()
	if err != nil {
		return err
	}
	// cgroup 限制更小时按限制算，否则容器里看到的是宿主机的内存
	if lim, ok := cgroupMemLimit(); ok && lim < total {
		used, uok := cgroupMemUsage()
		if uok && lim > 0 {
			s.MemPercent = 100 * float64(used) / float64(lim)
		} else {
			s.MemPercent = 100 * float64(total-avail) / float64(total)
		}
	} else {
		s.MemPercent = 100 * float64(total-avail) / float64(total)
	}
	if st, sa, serr := hostSwap(); serr == nil && st > 0 {
		s.SwapPercent = 100 * float64(st-sa) / float64(st)
	}
	return nil
}

func hostMem() (total, avail uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		v, perr := strconv.ParseUint(fs[1], 10, 64)
		if perr != nil {
			continue
		}
		v *= 1024 // meminfo 单位是 kB
		switch fs[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("读不到 MemTotal")
	}
	return total, avail, nil
}

func hostSwap() (total, free uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		v, perr := strconv.ParseUint(fs[1], 10, 64)
		if perr != nil {
			continue
		}
		v *= 1024
		switch fs[0] {
		case "SwapTotal:":
			total = v
		case "SwapFree:":
			free = v
		}
	}
	return total, free, nil
}

// cgroupMemLimit 读 cgroup 内存上限（v2 优先，v1 兜底）。
// 返回 ok=false 表示无限制或读不到。
func cgroupMemLimit() (uint64, bool) {
	// v2: /sys/fs/cgroup/memory.max，"max" 表示无限制
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" && s != "max" {
			if v, perr := strconv.ParseUint(s, 10, 64); perr == nil && v > 0 {
				return v, true
			}
		} else if s == "max" {
			return 0, false
		}
	}
	// v1
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			// v1 无限制时是个接近 2^63 的巨大数，视为无限制
			if v > 1<<60 {
				return 0, false
			}
			return v, v > 0
		}
	}
	return 0, false
}

func cgroupMemUsage() (uint64, bool) {
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			return v, true
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			return v, true
		}
	}
	return 0, false
}
