package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// 容量设置的持久化与 API。
//
// 出口上限与资源保护阈值存在 capacity.json，重启后沿用面板上改过的值。
// 但如果 systemd 启动命令里显式写了 -max <n>，每次重启都以命令行为准
// （main.go 里处理优先级），面板改的只在当前进程生效。

type persistedCapacity struct {
	MaxSlots       int  `json:"max_slots"`
	GuardEnabled   bool `json:"guard_enabled"`
	GuardThreshold int  `json:"guard_threshold"`
}

func capacityPath(dir string) string { return filepath.Join(dir, "capacity.json") }

// loadCapacity 从磁盘读容量设置，不存在返回 nil（用默认值）。
func loadCapacity(dir string) *persistedCapacity {
	blob, err := os.ReadFile(capacityPath(dir))
	if err != nil {
		return nil
	}
	var c persistedCapacity
	if err := json.Unmarshal(blob, &c); err != nil {
		return nil
	}
	return &c
}

// saveCapacity 落盘容量设置（0600，里面没有秘密，但保持与工作目录一致的权限习惯）。
func (m *Manager) saveCapacity() error {
	m.mu.RLock()
	c := persistedCapacity{MaxSlots: m.maxSlots}
	if m.guard != nil {
		c.GuardEnabled, c.GuardThreshold = m.guard.Config()
	}
	m.mu.RUnlock()
	blob, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := capacityPath(m.workDir) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, capacityPath(m.workDir))
}

// applyCapacity 改容量设置并落盘。maxSlots<=0 / threshold==0 表示不动；
// guardEnabled==nil 表示不动。返回中文错误直接展示给用户。
func (m *Manager) applyCapacity(maxSlots int, guardEnabled *bool, threshold int) error {
	if maxSlots > 0 {
		if err := m.SetMaxSlots(maxSlots); err != nil {
			return err
		}
	}
	m.mu.RLock()
	g := m.guard
	m.mu.RUnlock()
	if g != nil && (guardEnabled != nil || threshold != 0) {
		if err := g.SetConfig(guardEnabled, threshold); err != nil {
			return err
		}
	}
	return m.saveCapacity()
}

// capacityStatus 是 GET /api/capacity 返回的快照。
type capacityStatus struct {
	MaxSlots     int            `json:"max_slots"`
	Used         int            `json:"used"`
	Starting     int            `json:"starting"`
	GuardEnabled bool           `json:"guard_enabled"`
	Threshold    int            `json:"threshold"`
	Sample       ResourceSample `json:"sample"`
	AdmitOK      bool           `json:"admit_ok"`
	AdmitReason  string         `json:"admit_reason,omitempty"`
}

func apiCapacity(m *Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			m.mu.RLock()
			g := m.guard
			m.mu.RUnlock()
			st := capacityStatus{
				MaxSlots: m.MaxSlots(),
				Used:     len(m.Tunnels()),
				Starting: m.startingCount(),
			}
			if g != nil {
				st.GuardEnabled, st.Threshold = g.Config()
				st.Sample = g.Sample()
			}
			st.AdmitOK, st.AdmitReason = m.AdmissionCheck()
			writeJSON(w, http.StatusOK, st)
		case http.MethodPost:
			var req struct {
				MaxSlots     int   `json:"max_slots"`
				GuardEnabled *bool `json:"guard_enabled"`
				Threshold    int   `json:"threshold"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求解析失败: " + err.Error()})
				return
			}
			if err := m.applyCapacity(req.MaxSlots, req.GuardEnabled, req.Threshold); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"ok": "已保存"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET/POST"})
		}
	}
}

// parseMaxFlag 校验 --max 命令行参数。
func parseMaxFlag(n int) (int, error) {
	if n < 1 || n > maxExitSlots {
		return 0, fmt.Errorf("--max 须在 1~%d 之间", maxExitSlots)
	}
	return n, nil
}
