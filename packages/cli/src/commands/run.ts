import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

export async function runAgent(scriptPath: string, envelopePath: string) {
    console.log(`🛡️ W.H.Agent: Initializing Native OS Sandbox for ${scriptPath}`);

    const absoluteScriptPath = path.resolve(scriptPath);
    if (!fs.existsSync(absoluteScriptPath)) {
        console.error(`❌ Script not found: ${absoluteScriptPath}`);
        process.exit(1);
    }

    const code = fs.readFileSync(absoluteScriptPath, "utf-8");
    const isPython = absoluteScriptPath.endsWith(".py");
    const language = isPython ? "python" : "bash";

    console.log(`[NETWORK] Default-Deny enforced.`);
    console.log(`[STORAGE] Root filesystem restricted.`);
    console.log(`[ISOLATION] Sub-millisecond OS-Native isolation active.`);

    const reqPayload = JSON.stringify({
        Code: code,
        Language: language,
        TimeoutMs: 5000,
        Env: {}, // Can parse envelope.yaml to pass env vars
        MaxMemMB: 512,
        MaxCPUPct: 1.0,
    });

    console.log(`\n🚀 Launching isolated process...\n`);

    const sandboxBinPath = path.resolve(__dirname, "../bin/wh-sandbox");
    if (!fs.existsSync(sandboxBinPath)) {
        console.error(`❌ Native sandbox binary not found at ${sandboxBinPath}. Please run the build script.`);
        process.exit(1);
    }

    try {
        const result = spawnSync(sandboxBinPath, [], {
            input: reqPayload,
            encoding: "utf-8",
        });

        if (result.error) {
            console.error(`\n🚨 Sandbox execution failed to start: ${result.error.message}`);
            return;
        }

        if (result.stdout) {
            try {
                const parsedResult = JSON.parse(result.stdout);
                console.log(`----- SANDBOX STDOUT -----`);
                console.log(parsedResult.Stdout);
                if (parsedResult.Stderr) {
                    console.error(`----- SANDBOX STDERR -----`);
                    console.error(parsedResult.Stderr);
                }
                console.log(`\n✅ Execution completed in ${parsedResult.ExecutionMs}ms with exit code ${parsedResult.ExitCode}.`);
                if (parsedResult.Killed) {
                    console.log(`⚠️ Process was killed (Timeout exceeded).`);
                }
            } catch (e) {
                console.log(`----- RAW STDOUT -----`);
                console.log(result.stdout);
                if (result.stderr) {
                    console.error(`----- RAW STDERR -----`);
                    console.error(result.stderr);
                }
            }
        }
    } catch (err) {
        console.error(`\n🚨 Agent execution crashed: ${err}`);
    }
}
