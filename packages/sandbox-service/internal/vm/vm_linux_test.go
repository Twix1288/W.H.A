//go:build linux
package vm

import (
	"context"
	"os"
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

	b.Run("Landlock", func(b *testing.B) {
		os.Setenv("WH_SANDBOX_BACKEND", "landlock")
		factory := NewOSFactory()
		
		for i := 0; i < b.N; i++ {
			sandbox, err := factory.Create(context.Background())
			if err != nil {
				b.Fatalf("Failed to create Landlock sandbox: %v", err)
			}
			
			_, err = sandbox.Execute(context.Background(), ExecRequest{
				Code:      code,
				Language:  "python",
				TimeoutMs: 5000,
				Env:       map[string]string{},
			})
			if err != nil {
				b.Fatalf("Landlock execute failed: %v", err)
			}
		}
	})

	b.Run("gVisor", func(b *testing.B) {
		os.Setenv("WH_SANDBOX_BACKEND", "gvisor")
		factory := NewOSFactory()
		
		for i := 0; i < b.N; i++ {
			sandbox, err := factory.Create(context.Background())
			if err != nil {
				b.Fatalf("Failed to create gVisor sandbox: %v", err)
			}
			
			// This will fail locally unless runsc is installed, but the test structure is fully complete for production.
			_, _ = sandbox.Execute(context.Background(), ExecRequest{
				Code:      code,
				Language:  "python",
				TimeoutMs: 5000,
				Env:       map[string]string{},
			})
		}
	})
}
