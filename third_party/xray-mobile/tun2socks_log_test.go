//go:build android || windows

package XRay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
	glog "gvisor.dev/gvisor/pkg/log"
)

// Every flow the bridge carries is logged at Info with its destination, and
// every failed dial at Warn. Neither may be written anywhere.
//
// The lines are the ones tun2socks itself writes, sent through its own
// logging calls, with stderr pointed at a file for as long as the logger is
// being built -- that is the moment it decides where to write.
func TestNoFlowReachesTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stderr")
	capture, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	real := os.Stderr
	os.Stderr = capture
	quietBridge()
	os.Stderr = real
	// Back onto the real stderr for whatever runs after this.
	t.Cleanup(quietBridge)

	t2slog.Infof("[TCP] %s <-> %s", "198.18.0.1:50000", "203.0.113.7:443")
	t2slog.Warnf("[TCP] dial %s: %v", "203.0.113.7:443", "connection refused")
	t2slog.Errorf("the capture works")

	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(written), "the capture works") {
		t.Fatalf("nothing was captured, so nothing below would prove anything: %q", written)
	}
	if strings.Contains(string(written), "203.0.113.7") {
		t.Fatalf("a destination was written to the log:\n%s", written)
	}
}

// What gVisor's logger was set to before any test ran, and so before the
// test above could install anything itself.
var stackLoggedInfoAtStartup bool

func TestMain(m *testing.M) {
	stackLoggedInfoAtStartup = glog.IsLogging(glog.Info)
	os.Exit(m.Run())
}

// That the replacement happens on its own, with nobody calling it. tun2socks
// keeps its logger private, but its own leaves gVisor's at Info and ours
// leaves it at Warning.
func TestTheQuietLoggerIsInstalledAtStartup(t *testing.T) {
	if stackLoggedInfoAtStartup {
		t.Fatal("tun2socks started on the logger it installs for itself")
	}
}
