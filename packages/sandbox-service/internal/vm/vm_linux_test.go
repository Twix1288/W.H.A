//go:build linux

package vm

import (
	"context"
	"strings"
	"testing"
)

func BenchmarkLandlockVsGvisor(b *testing.B) {
	// A heavy I/O python script mimicking a real MCP tool workload
	code := `
import os
import subprocess

def heavy_io():
    # Write to 100 files
    for i in range(100):
        with open(f"temp_{i}.txt", "w") as f:
            f.write("test data")
            
    # Read from 100 files
    for i in range(100):
        with open(f"temp_{i}.txt", "r") as f:
            data = f.read()
            
    # Spawn a subprocess
    subprocess.run(["ls", "-l"])
    
heavy_io()
`

	// Both Linux backends now fail closed (no real isolation implemented yet), so
	// this benchmark measures the fail-closed path. Env is set with b.Setenv so it
	// is restored afterwards and does not leak into other tests in this process.
	b.Run("Landlock", func(b *testing.B) {
		b.Setenv("WH_SANDBOX_BACKEND", "landlock")
		factory := NewOSFactory()

		for i := 0; i < b.N; i++ {
			sandbox, err := factory.Create(context.Background())
			if err != nil {
				b.Fatalf("Failed to create Landlock sandbox: %v", err)
			}

			// Fails closed — an error is the expected, correct outcome.
			if _, err := sandbox.Execute(context.Background(), ExecRequest{
				Code:      code,
				Language:  "python",
				TimeoutMs: 5000,
				Env:       map[string]string{},
			}); err == nil {
				b.Fatalf("Landlock backend executed instead of failing closed")
			}
		}
	})

	b.Run("gVisor", func(b *testing.B) {
		b.Setenv("WH_SANDBOX_BACKEND", "gvisor")
		factory := NewOSFactory()

		for i := 0; i < b.N; i++ {
			sandbox, err := factory.Create(context.Background())
			if err != nil {
				b.Fatalf("Failed to create gVisor sandbox: %v", err)
			}

			// gVisor also fails closed until an isolated OCI rootfs lands.
			if _, err := sandbox.Execute(context.Background(), ExecRequest{
				Code:      code,
				Language:  "python",
				TimeoutMs: 5000,
				Env:       map[string]string{},
			}); err == nil {
				b.Fatalf("gVisor backend executed instead of failing closed")
			}
		}
	})
}

// The default Linux backend must FAIL CLOSED: it must never run untrusted code
// with no isolation. Until real Landlock enforcement lands, Execute must return
// an error instead of executing the payload.
func TestLandlockFailsClosed(t *testing.T) {
	s, err := (&LandlockFactory{}).Create(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := s.Execute(context.Background(), ExecRequest{
		Code:     "open('/etc/shadow').read()",
		Language: "python",
	})
	if err == nil {
		t.Fatalf("landlock backend executed the payload instead of failing closed (result=%+v)", res)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// The gVisor backend must also FAIL CLOSED. `runsc do` intercepts syscalls but
// maps the host filesystem into the sandbox and leaves network egress open, so it
// does not actually confine untrusted code. Until an isolated OCI rootfs +
// --network=none lands, Execute must refuse rather than run with fake isolation.
func TestGvisorFailsClosed(t *testing.T) {
	s, err := (&GvisorFactory{}).Create(context.Background())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := s.Execute(context.Background(), ExecRequest{
		Code:     "open('/etc/shadow').read()",
		Language: "python",
	})
	if err == nil {
		t.Fatalf("gvisor backend executed the payload instead of failing closed (result=%+v)", res)
	}
	if !strings.Contains(err.Error(), "isolation") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// The default factory (no WH_SANDBOX_BACKEND set) must select the fail-closed
// Landlock backend rather than silently running unsandboxed.
func TestDefaultBackendIsFailClosed(t *testing.T) {
	t.Setenv("WH_SANDBOX_BACKEND", "")
	if f := NewOSFactory(); func() bool { _, ok := f.(*LandlockFactory); return !ok }() {
		t.Fatalf("default backend is %T, want *LandlockFactory (fail-closed)", f)
	}
}
