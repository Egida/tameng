package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/koodoxz/tameng/internal/config"
	"github.com/koodoxz/tameng/internal/logger"
)

// TestHandleHeimdallReport_ConcurrentReportsDoNotLoseUpdates guards against a
// lost-update race in data/attacker-memory.json: handleHeimdallReport does a
// read-modify-write with no synchronization, so two concurrent reports each
// read the same on-disk state, apply their own update in memory, and the
// second write silently clobbers the first's. This fires many concurrent
// reports for distinct IPs and asserts every one survives to disk.
func TestHandleHeimdallReport_ConcurrentReportsDoNotLoseUpdates(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir("data", 0755); err != nil {
		t.Fatalf("failed to create data dir: %v", err)
	}

	s := &Server{
		log:           logger.New("test"),
		cfg:           &config.Config{Ecosystem: config.EcosystemConfig{}},
		stats:         &Stats{StartTime: time.Now()},
		heimdallDedup: make(map[string]time.Time),
	}

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			body := []byte(fmt.Sprintf(
				`{"ip":"203.0.113.%d","threat_type":"port_scan","severity":5,"confidence":0.8}`, i))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/heimdall/report", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			s.handleHeimdallReport(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("report %d: expected 200, got %d: %s", i, rec.Code, rec.Body.String())
			}
		}(i)
	}
	close(start)
	wg.Wait()

	data, err := os.ReadFile("data/attacker-memory.json")
	if err != nil {
		t.Fatalf("failed to read attacker-memory.json: %v", err)
	}
	var memory map[string]interface{}
	if err := json.Unmarshal(data, &memory); err != nil {
		t.Fatalf("failed to parse attacker-memory.json: %v", err)
	}
	actors, _ := memory["actors"].(map[string]interface{})
	if len(actors) != n {
		t.Fatalf("lost update: expected %d actors persisted, got %d", n, len(actors))
	}
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if _, ok := actors[ip]; !ok {
			t.Errorf("actor %s missing from persisted attacker-memory.json (lost update)", ip)
		}
	}
}
