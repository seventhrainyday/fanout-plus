package main

import (
	"testing"
	"time"
)

func TestResourceSampler(t *testing.T) {
	g := NewResourceGuard(true, 80)
	g.Start()
	defer g.Stop()
	// 等两轮采样（首轮没有 CPU 差值）
	time.Sleep(2500 * time.Millisecond)
	s := g.Sample()
	if s.Updated.IsZero() {
		t.Fatal("采样器没有产出样本")
	}
	if s.Err != "" {
		t.Fatalf("采样报错: %s", s.Err)
	}
	if s.MemPercent <= 0 || s.MemPercent > 100 {
		t.Errorf("内存占用率异常: %.1f", s.MemPercent)
	}
	if s.CPUPercent < 0 || s.CPUPercent > 100 {
		t.Errorf("CPU 占用率异常: %.1f", s.CPUPercent)
	}
}

func TestGuardDisabledAlwaysAdmits(t *testing.T) {
	g := NewResourceGuard(false, 80)
	// 没启动采样、保护关闭：永远放行
	if ok, _ := g.AdmissionCheck(); !ok {
		t.Error("保护关闭时应当放行")
	}
}

func TestGuardFailClosed(t *testing.T) {
	g := NewResourceGuard(true, 80)
	// 没启动采样：状态未知，fail-closed 拒绝
	if ok, reason := g.AdmissionCheck(); ok {
		t.Error("无采样时应当拒绝（fail-closed）")
	} else if reason == "" {
		t.Error("拒绝时应当给出原因")
	}
}

func TestGuardThresholdValidation(t *testing.T) {
	g := NewResourceGuard(true, 80)
	if err := g.SetConfig(nil, 30); err == nil {
		t.Error("阈值 30（低于下限）应当被拒绝")
	}
	if err := g.SetConfig(nil, 99); err == nil {
		t.Error("阈值 99（高于上限）应当被拒绝")
	}
	if err := g.SetConfig(nil, 90); err != nil {
		t.Errorf("阈值 90 应当接受: %v", err)
	}
	_, th := g.Config()
	if th != 90 {
		t.Errorf("阈值没改过去: %d", th)
	}
	off := false
	if err := g.SetConfig(&off, 0); err != nil {
		t.Fatal(err)
	}
	if on, _ := g.Config(); on {
		t.Error("开关没关掉")
	}
}

func TestSetMaxSlotsValidation(t *testing.T) {
	m := NewManager(20, t.TempDir())
	if err := m.SetMaxSlots(0); err == nil {
		t.Error("上限 0 应当被拒绝")
	}
	if err := m.SetMaxSlots(255); err == nil {
		t.Error("上限 255（超技术上限）应当被拒绝")
	}
	if err := m.SetMaxSlots(254); err != nil {
		t.Errorf("上限 254 应当接受: %v", err)
	}
	if m.MaxSlots() != 254 {
		t.Errorf("上限没改过去: %d", m.MaxSlots())
	}
	// 调小不影响已用槽位计数逻辑：AdmissionCheck 按新上限算
	m2 := NewManager(300, t.TempDir()) // 构造时钳制到 254
	if m2.MaxSlots() != 254 {
		t.Errorf("构造时应钳制到 254，实际 %d", m2.MaxSlots())
	}
}

func TestAdmissionCheckSlots(t *testing.T) {
	m := NewManager(1, t.TempDir())
	// 造一个占位隧道（不真正启动）
	m.tunnels[1] = &Tunnel{Slot: 1, Status: "up"}
	if ok, reason := m.AdmissionCheck(); ok {
		t.Error("槽位已满应当拒绝")
	} else if reason == "" {
		t.Error("拒绝时应当给出原因")
	}
}
