package executor

import (
    "context"
    "strings"
    "testing"

    "wh-agent/sandbox-service/internal/vm"
)

func TestExecutor_MacSandbox(t *testing.T) {
    // Only test on Mac OS but this code compiles everywhere due to testing pkg not being strict
}

func TestExecutePython_Success(t *testing.T) {
    factory := vm.NewOSFactory()
    engine := NewEngine(5, factory)

    req := vm.ExecRequest{
        Language: "python",
        Code:     `print("hello from OS-native sandbox")`,
    }

    res, err := engine.Execute(context.Background(), req)
    if err != nil {
        t.Fatalf("Expected success, got error: %v", err)
    }

    if res.ExitCode != 0 {
        t.Fatalf("Expected exit code 0, got %d, stderr: %s", res.ExitCode, res.Stderr)
    }

    if !strings.Contains(res.Stdout, "hello from OS-native sandbox") {
        t.Fatalf("Expected stdout to contain string, got: %s", res.Stdout)
    }
}
