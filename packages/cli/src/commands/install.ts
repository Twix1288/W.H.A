import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as https from "node:https";
import * as os from "node:os";
import * as path from "node:path";
import chalk from "chalk";
import * as tar from "tar";
import { checkPackageName } from "../core-scanner/threat-intel/cve-database";
// Import the data statically so the bundler includes it in dist/. A runtime
// require("./popular-packages.json") silently fails in the published CLI (the
// JSON is not copied next to the bundle), which disabled typosquat detection.
import popularPackages from "./popular-packages.json";

interface InstallOptions {
	force: boolean;
	dryRun: boolean;
	pkgVersion?: string;
	/** Custom npm registry. Applied to BOTH the vet and the install. */
	registryUrl?: string;
}

const MAX_TARBALL_SIZE = 50 * 1024 * 1024; // 50MB
const FETCH_TIMEOUT_MS = 10000;

function levenshtein(a: string, b: string): number {
	const dp = Array.from({ length: a.length + 1 }, (_, i) => [
		i,
		...Array(b.length).fill(0),
	]);
	for (let j = 0; j <= b.length; j++) dp[0][j] = j;
	for (let i = 1; i <= a.length; i++) {
		for (let j = 1; j <= b.length; j++) {
			dp[i][j] =
				a[i - 1] === b[j - 1]
					? dp[i - 1][j - 1]
					: 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
		}
	}
	return dp[a.length][b.length];
}

const DEFAULT_REGISTRY = "https://registry.npmjs.org";

/**
 * Validate and normalize a registry URL.
 *
 * `--registry-url` used to be accepted, documented, and then COMPLETELY IGNORED:
 * metadata was always read from public npm while `npm install` obeyed the local
 * npm config. For anyone with a private registry that is worse than no flag at
 * all — the tool vets the PUBLIC package of that name and then installs a
 * different, unvetted package from the private registry, under a green report.
 * The URL is now honored for both halves.
 */
export function normalizeRegistry(raw: string | undefined): string {
	if (!raw) return DEFAULT_REGISTRY;
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		throw new Error(`Invalid --registry-url: ${raw}`);
	}
	if (url.protocol !== "https:" && url.protocol !== "http:") {
		throw new Error(
			`Unsupported --registry-url protocol '${url.protocol}' (expected http or https)`,
		);
	}
	if (url.protocol === "http:") {
		console.log(
			chalk.yellow(
				`⚠️  --registry-url uses plaintext http (${url.host}); package metadata and any credentials are unencrypted in transit.`,
			),
		);
	}
	// Drop a trailing slash so path joins are predictable.
	return url.toString().replace(/\/+$/, "");
}

function fetchPackageMetadata(
	packageName: string,
	version = "latest",
	registry: string = DEFAULT_REGISTRY,
): Promise<any> {
	return new Promise((resolve, reject) => {
		const base = registry.startsWith("http:") ? http : https;
		const req = base.get(
			`${registry}/${packageName}`,
			(res) => {
				if (res.statusCode === 404) {
					return reject(new Error("PACKAGE_NOT_FOUND"));
				}
				if (res.statusCode !== 200) {
					return reject(new Error(`Registry returned ${res.statusCode}`));
				}
				let data = "";
				res.on("data", (chunk) => {
					data += chunk;
				});
				res.on("end", () => {
					try {
						const meta = JSON.parse(data);
						const resolvedVersion =
							version === "latest" ? meta["dist-tags"]?.latest : version;
						const manifest = meta.versions?.[resolvedVersion];
						if (!manifest) {
							return reject(new Error(`Version ${resolvedVersion} not found`));
						}
						resolve(manifest);
					} catch (err) {
						reject(err);
					}
				});
			},
		);

		req.on("error", reject);
		req.setTimeout(FETCH_TIMEOUT_MS, () => {
			req.destroy();
			reject(new Error("TIMEOUT"));
		});
	});
}

/**
 * Packages that are legitimately close to a popular name. Verified real, widely
 * used packages only — every entry is a hole in the typosquat gate, so additions
 * need justification.
 */
const KNOWN_LEGITIMATE = new Set([
	"preact", // distance 1 from `react`
	"ms", // distance 1 from `ws`
	"qs", // distance 1 from `ws`
	"chai", // distance 2 from `chalk`
	"vite", // distance 2 from `vue`
	"jose", // distance 2 from `joi`
	"tslib", // distance 2 from `slib`-likes
	"undici", // distance 2 from `unidici` typos
]);

export function checkTyposquat(packageName: string) {
	const popular = popularPackages as string[];

	// A package that is ITSELF on the popular list cannot be a typosquat of another
	// popular package — it is the real thing. Without this guard the check
	// hard-blocked 66 of the 304 packages on its own reference list, including
	// express, vue, redis, zod, next, jest, cors and mysql (`express`/`cypress` are
	// Levenshtein distance 2 apart). A supply-chain gate that refuses the most
	// popular packages on npm gets switched off, and a gate nobody runs protects
	// nobody — so this false-positive class was the single biggest threat to the
	// command's usefulness.
	if (popular.includes(packageName)) {
		console.log(
			chalk.green(
				`✅ '${packageName}' is a known-popular package name (exact match) — not a typosquat.`,
			),
		);
		return { risky: false, similarTo: [] };
	}

	// Known-legitimate packages that happen to sit within an edit or two of a
	// popular name. Without this they are permanently unusable through the gate:
	// `preact` is distance 1 from `react`, `ms` is distance 1 from `ws`.
	//
	// This is the same idea as the popular list — a set of names we know are real —
	// so it is checked the same way. It is deliberately small and requires evidence
	// (a genuinely well-known package) to extend; guessing at entries would punch
	// holes in the gate.
	if (KNOWN_LEGITIMATE.has(packageName)) {
		console.log(
			chalk.green(
				`✅ '${packageName}' is a known-legitimate package that resembles a popular name — not a typosquat.`,
			),
		);
		return { risky: false, similarTo: [] };
	}

	// Short names are inherently close to one another, so the distance signal is
	// weak there; require an exact-length match before trusting a single edit.
	const maxDistance = packageName.length <= 4 ? 1 : 2;

	const close = popular.filter((p) => {
		if (p === packageName) return false;
		const dist = levenshtein(p, packageName);
		if (dist === 0 || dist > maxDistance) return false;
		return Math.abs(p.length - packageName.length) <= 2;
	});

	if (close.length > 0) {
		console.log(
			chalk.red(
				`⚠️  '${packageName}' is suspiciously close to: ${close.join(", ")}`,
			),
		);
		console.log(
			chalk.yellow(
				`   This could be a typosquat. Verify before installing.\n   ℹ️  Typosquat check compares against the top ${popularPackages.length} npm packages only; lesser-known package names aren't covered.`,
			),
		);
		return { risky: true, similarTo: close };
	}
	return { risky: false, similarTo: [] };
}

function checkLifecycleScripts(packageName: string, manifest: any) {
	const scripts = manifest.scripts || {};
	const dangerous = ["preinstall", "install", "postinstall"];
	const found = dangerous.filter((s) => scripts[s]);

	if (found.length > 0) {
		console.log(
			chalk.yellow(
				`ℹ️  ${packageName} runs code automatically on install via: ${found.join(", ")}`,
			),
		);
		for (const s of found) {
			console.log(chalk.gray(`   ${s}: ${scripts[s]}`));
		}
		return { hasScripts: true, scripts: found };
	}
	console.log(chalk.green(`✅ No install-time lifecycle scripts found.`));
	return { hasScripts: false, scripts: [] };
}

function checkProvenance(packageName: string, manifest: any) {
	const hasAttestation = !!manifest.dist?.attestations?.url;

	if (hasAttestation) {
		console.log(
			chalk.green(
				`✅ ${packageName} has npm provenance (Sigstore-backed build attestation).`,
			),
		);
		return { verified: true };
	}
	console.log(
		chalk.gray(
			`ℹ️  ${packageName} has no provenance attestation (most packages don't yet — not necessarily a red flag).`,
		),
	);
	return { verified: false };
}

function downloadTarball(url: string, destPath: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const file = fs.createWriteStream(destPath);
		let downloadedBytes = 0;

		const req = https.get(url, (res) => {
			if (res.statusCode === 301 || res.statusCode === 302) {
				// Follow redirect (naive implementation for tarball redirects)
				if (res.headers.location) {
					return downloadTarball(res.headers.location, destPath)
						.then(resolve)
						.catch(reject);
				}
			}

			if (res.statusCode !== 200) {
				return reject(new Error(`Download failed: ${res.statusCode}`));
			}

			res.on("data", (chunk) => {
				downloadedBytes += chunk.length;
				if (downloadedBytes > MAX_TARBALL_SIZE) {
					req.destroy();
					file.close();
					reject(new Error("TARBALL_TOO_LARGE"));
				}
			});

			res.pipe(file);
			file.on("finish", () => {
				file.close();
				resolve();
			});
		});

		req.on("error", reject);
		req.setTimeout(FETCH_TIMEOUT_MS, () => {
			req.destroy();
			file.close();
			reject(new Error("TIMEOUT"));
		});
	});
}

/**
 * Source extensions the secret/eval scan reads. Case-insensitive and inclusive of
 * ESM/CJS/JSX/TSX — the previous filter was `/\.(js|ts|json)$/` with no `i` flag.
 */
export const SCANNABLE_SOURCE_RE = /\.(?:js|cjs|mjs|jsx|ts|cts|mts|tsx|json|sh|bash|py)$/i;

/** Per-file cap for the secret scan; larger files are reported as unscanned. */
const MAX_SCAN_FILE_BYTES = 5 * 1024 * 1024;

/** Longest line beyond which a file is treated as minified. */
const MINIFIED_LINE_THRESHOLD = 5000;

/**
 * True when a file is vendored or bundled output rather than authored source.
 *
 * Heuristic pattern hits inside such files are reported but do not hard block:
 * `next` (and any package shipping a webpack bundle) tripped "eval of remote
 * content" on `dist/compiled/webpack/bundle5.js` and was refused outright. Real
 * secrets — AWS keys, private keys — still block from anywhere.
 */
export function isVendorBundle(relativePath: string, content: string): boolean {
	const p = relativePath.replace(/\\/g, "/").toLowerCase();
	if (/(?:^|\/)(?:dist|build|compiled|vendor|node_modules|umd|esm|cjs)\//.test(p)) {
		return true;
	}
	if (/\.(?:min|bundle|pack)\.(?:js|mjs|cjs)$/.test(p)) return true;
	// Minified: one enormous line.
	let longest = 0;
	let current = 0;
	for (let i = 0; i < content.length; i++) {
		if (content[i] === "\n") {
			if (current > longest) longest = current;
			current = 0;
			if (longest > MINIFIED_LINE_THRESHOLD) return true;
		} else {
			current++;
		}
	}
	return Math.max(longest, current) > MINIFIED_LINE_THRESHOLD;
}

const SECRET_PATTERNS = [
	{ name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
	{ name: "Private Key", re: /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/ },
	{
		name: "Generic API Key assignment",
		re: /api[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9_-]{20,})['"]/i,
	},
	{
		// HEURISTIC, not a secret: minified/bundled vendor output legitimately
		// contains `eval(` and URLs (webpack's eval devtool, for instance). Matching
		// it inside a bundle is not evidence of malice, so this rule does not hard
		// block when the hit is in vendored/minified output — see isVendorBundle.
		heuristic: true,
		name: "eval of remote content",
		// The second alternative was `eval\(.*http` — an UNBOUNDED `.*` that rescans
		// to end-of-line from every `eval(` occurrence, giving O(n²) behaviour on
		// attacker-published package contents. Measured: 20KB 63ms, 40KB 247ms,
		// 80KB 982ms, 160KB 3.9s, 320KB 15.8s — a hostile package could stall its own
		// security review, and a gate that hangs is a gate people learn to skip.
		// A bounded negated class matches the same real cases in linear time.
		re: /eval\(\s*(?:await\s+)?fetch|eval\([^\n]{0,200}?https?:/i,
	},
];

async function scanTarball(packageName: string, manifest: any) {
	const tarballUrl = manifest.dist?.tarball;
	if (!tarballUrl) {
		console.log(chalk.gray(`ℹ️  No tarball URL found in manifest.`));
		// No tarball means the source was never inspected. Report that rather than
		// returning an empty (and therefore clean-looking) result.
		return {
			findings: [],
			binaries: [],
			unscanned: ["no tarball URL in manifest — source never inspected"],
			scanAborted: true,
		};
	}

	const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wh-agent-scan-"));
	const tarPath = path.join(tmpDir, "pkg.tgz");

	try {
		await downloadTarball(tarballUrl, tarPath);
	} catch (err: any) {
		if (err.message === "TARBALL_TOO_LARGE") {
			console.log(
				chalk.yellow(
					`⚠️  Tarball exceeds 50MB limit; skipping static source scan.`,
				),
			);
			fs.rmSync(tmpDir, { recursive: true, force: true });
			return {
				findings: [],
				binaries: [],
				unscanned: ["tarball exceeds 50MB — static source scan skipped"],
				scanAborted: true,
			};
		}
		throw err;
	}

	try {
		await tar.x({
			file: tarPath,
			cwd: tmpDir,
			strip: 0,
			filter: (entryPath) => {
				const resolved = path.resolve(tmpDir, entryPath);
				return resolved.startsWith(tmpDir); // reject anything that escapes tmpDir
			},
		});
	} catch (err) {
		console.log(chalk.red(`⚠️  Failed to extract tarball safely: ${err}`));
		fs.rmSync(tmpDir, { recursive: true, force: true });
		return {
			findings: [
				{ file: "tarball", pattern: "Extraction failure", redacted: "n/a", blocking: true },
			],
			binaries: [],
			unscanned: ["tarball could not be extracted safely — source never inspected"],
			scanAborted: true,
		};
	}

	const findings: {
		file: string;
		pattern: string;
		redacted: string;
		blocking: boolean;
	}[] = [];
	const binaries: string[] = [];
	/** Files we could not analyze — reported, never silently dropped. */
	const unscanned: string[] = [];

	function walk(dir: string) {
		const entries = fs.readdirSync(dir);
		for (const f of entries) {
			const full = path.join(dir, f);
			// lstat, not stat: a symlink in the extracted tarball must never be
			// followed — it can point outside the sandbox directory or form a cycle
			// that makes this recursion non-terminating.
			const stat = fs.lstatSync(full);
			if (stat.isSymbolicLink()) {
				unscanned.push(`${full.replace(tmpDir + path.sep, "")} (symlink — not followed)`);
				continue;
			}
			if (stat.isDirectory()) {
				walk(full);
				continue;
			}

			const relativePath = full.replace(tmpDir + path.sep, "");

			// Flag native binaries
			if (/\.(node|exe|dll|so|dylib)$/i.test(f)) {
				binaries.push(relativePath);
				continue;
			}

			// Also flag unusually large files that might be blobs (e.g. > 10MB)
			if (stat.size > 10 * 1024 * 1024 && !/\.(js|ts|json|md|txt)$/i.test(f)) {
				binaries.push(
					`${relativePath} (Large blob: ${Math.round(stat.size / 1024 / 1024)}MB)`,
				);
				continue;
			}

			// Previously `/\.(js|ts|json)$/` with NO `i` flag: `.mjs`, `.cjs`, `.jsx`,
			// `.tsx` and any uppercase `.JS` were skipped entirely, so a malicious ESM
			// package was reported "clean". Modern npm packages ship `.mjs`/`.cjs` by
			// default, which made this the common case rather than an edge case.
			if (!SCANNABLE_SOURCE_RE.test(f)) continue;

			// Bound the work per file. An oversized source file is NOT silently
			// skipped — it is surfaced as unscanned so a green report never implies
			// "we looked at everything".
			if (stat.size > MAX_SCAN_FILE_BYTES) {
				unscanned.push(
					`${relativePath} (${Math.round(stat.size / 1024 / 1024)}MB — exceeds ${MAX_SCAN_FILE_BYTES / 1024 / 1024}MB scan cap)`,
				);
				continue;
			}

			const content = fs.readFileSync(full, "utf-8");
			const vendored = isVendorBundle(relativePath, content);
			for (const { name, re, heuristic } of SECRET_PATTERNS) {
				const match = content.match(re);
				if (match) {
					// match[1] is the captured group if any, otherwise match[0]
					const secret = match[1] || match[0];
					const redacted =
						secret.length > 8 ? secret.slice(0, 4) + "***" : "***";
					findings.push({
						file: relativePath,
						pattern: name,
						redacted,
						// A heuristic hit in vendored/minified output is informational.
						blocking: !(heuristic === true && vendored),
					});
				}
			}
		}
	}

	// A walk failure used to be swallowed, which silently converted an ABORTED scan
	// into a "no suspicious patterns found" pass — the worst possible failure mode
	// for a security gate. The error is now recorded as a finding so the caller
	// treats the package as un-vetted (fail closed) rather than clean.
	let walkError: string | null = null;
	try {
		walk(tmpDir);
	} catch (e) {
		walkError = e instanceof Error ? e.message : String(e);
		unscanned.push(`scan aborted: ${walkError}`);
	}

	fs.rmSync(tmpDir, { recursive: true, force: true });

	if (findings.length > 0) {
		const blocking = findings.filter((f) => f.blocking);
		const informational = findings.filter((f) => !f.blocking);
		if (blocking.length > 0) {
			console.log(chalk.red(`⚠️  Suspicious patterns found in package source:`));
			for (const f of blocking) {
				console.log(chalk.red(`   ${f.file}: ${f.pattern} (${f.redacted})`));
			}
		}
		if (informational.length > 0) {
			console.log(
				chalk.yellow(
					`ℹ️  Heuristic pattern hits in vendored/minified output (not treated as blockers):`,
				),
			);
			for (const f of informational) {
				console.log(chalk.gray(`   ${f.file}: ${f.pattern} (${f.redacted})`));
			}
		}
	} else {
		console.log(
			chalk.green(`✅ No known suspicious patterns found in source.`),
		);
	}

	if (binaries.length > 0) {
		console.log(
			chalk.yellow(
				`ℹ️  This package ships native binaries or large blobs which were not scanned:\n   ${binaries.join("\n   ")}`,
			),
		);
	}

	return { findings, binaries, unscanned, scanAborted: walkError !== null };
}

export async function installAgent(pkgName: string, options: InstallOptions) {
	console.log(`\n📦 W.H.Agent Supply Chain: Checking ${pkgName}`);

	let hasBlocker = false;
	let hasInfo = false;

	// 1. Typosquat Check
	const typoResult = checkTyposquat(pkgName);
	if (typoResult.risky) hasBlocker = true;

	// 1a. Known-malicious / compromised package DB — checked EARLY (before the npm
	// metadata fetch) so a name that has since been pulled from the registry (which
	// would 404 the fetch and exit) is still blocked, and so an explicit
	// `--pkg-version` of a compromised release is caught with no network at all.
	// The threat-intel DB is what `inspect-mcp` already consults; `install` never
	// did, so a package on our own known-compromised list installed clean.
	let dbReported = false;
	const reportDbHit = (hit: ReturnType<typeof checkPackageName>, version?: string) => {
		if (!hit || dbReported) return;
		dbReported = true;
		hasBlocker = true;
		const label =
			hit.type === "compromised"
				? "COMPROMISED"
				: hit.type === "typosquat"
					? "KNOWN TYPOSQUAT"
					: "MALICIOUS";
		console.error(
			chalk.red(
				`\n🚨 Known-${label} package: ${pkgName}${version ? `@${version}` : ""}`,
			),
		);
		console.error(chalk.red(`   ${hit.description}`));
		if (hit.legitimatePackage)
			console.error(
				chalk.gray(`   Legitimate package is likely: ${hit.legitimatePackage}`),
			);
	};
	const earlyHit = checkPackageName(pkgName, options.pkgVersion);
	// Hard-block early (before any fetch) for an unconditionally-bad NAME
	// (malicious / typosquat), or for a compromised package only when a specific
	// bad version was explicitly requested. A compromised package with NO explicit
	// version is deferred to the resolved-version check below, so we don't
	// false-positive a legitimate package whose *latest* is fine (only some old
	// version was tainted).
	if (earlyHit && (earlyHit.type !== "compromised" || !!options.pkgVersion)) {
		reportDbHit(earlyHit, options.pkgVersion);
		if (!options.force) {
			// Refuse outright — don't even fetch metadata (the name may 404 and exit
			// with a misleading "not found" instead of a block). Exit 2 = hard blocker.
			console.error(
				chalk.red(
					`   Refusing to fetch or install a known-bad package. Re-run with --force only if you have independently verified it.`,
				),
			);
			process.exit(2);
		}
	}

	// Resolved once and used for BOTH metadata fetch and `npm install`, so the
	// package we vet is always the package we install.
	let registry: string;
	try {
		registry = normalizeRegistry(options.registryUrl);
	} catch (err: any) {
		console.error(chalk.red(`❌ ${err.message}`));
		process.exit(1);
	}
	if (registry !== DEFAULT_REGISTRY) {
		console.log(chalk.gray(`ℹ️  Using registry: ${registry}`));
	}

	let manifest: Awaited<ReturnType<typeof fetchPackageMetadata>>;
	try {
		manifest = await fetchPackageMetadata(
			pkgName,
			options.pkgVersion || "latest",
			registry,
		);
	} catch (err: any) {
		if (err.message === "PACKAGE_NOT_FOUND") {
			console.error(chalk.red(`❌ Package '${pkgName}' not found on npm.`));
		} else if (err.message === "TIMEOUT") {
			console.error(chalk.red(`❌ Registry request timed out.`));
		} else {
			console.error(
				chalk.red(`❌ Failed to fetch package metadata: ${err.message}`),
			);
		}
		process.exit(1);
	}

	// 1b. Re-check with the RESOLVED version now that we have the manifest — this
	// catches the case where `latest` itself resolves to a known-compromised release
	// (the early check only saw an unresolved "latest"/undefined). Deduped so the
	// same hit is never printed twice.
	const resolvedVersion =
		(manifest as { version?: string })?.version ?? options.pkgVersion;
	reportDbHit(checkPackageName(pkgName, resolvedVersion), resolvedVersion);

	// 2. Lifecycle Scripts Check
	const lifecycleResult = checkLifecycleScripts(pkgName, manifest);
	if (lifecycleResult.hasScripts) hasInfo = true;

	// 3. Provenance Check
	checkProvenance(pkgName, manifest);

	// 4. Tarball Scan
	let tarballResult: Awaited<ReturnType<typeof scanTarball>>;
	try {
		tarballResult = await scanTarball(pkgName, manifest);
		// Only genuinely blocking findings abort the install; heuristic hits inside
		// vendored/minified output are surfaced as information.
		if (tarballResult.findings.some((f) => f.blocking)) hasBlocker = true;
		else if (tarballResult.findings.length > 0) hasInfo = true;
		if (tarballResult.binaries.length > 0) hasInfo = true;

		// Anything we could not analyze is surfaced, never silently dropped: a green
		// report must not imply coverage we did not have.
		if (tarballResult.unscanned.length > 0) {
			console.log(
				chalk.yellow(
					`⚠️  ${tarballResult.unscanned.length} item(s) could not be scanned:`,
				),
			);
			for (const u of tarballResult.unscanned.slice(0, 10)) {
				console.log(chalk.gray(`     - ${u}`));
			}
			if (tarballResult.unscanned.length > 10) {
				console.log(
					chalk.gray(`     … and ${tarballResult.unscanned.length - 10} more`),
				);
			}
			hasInfo = true;
		}
		// An aborted scan is not a pass. Treat it as a blocker so the user makes an
		// explicit decision (--force) instead of trusting an incomplete review.
		if (tarballResult.scanAborted) {
			console.log(
				chalk.red(
					`🛑 Source scan did not complete — this package has NOT been fully vetted.`,
				),
			);
			hasBlocker = true;
		}
	} catch (err: any) {
		console.log(chalk.red(`⚠️  Error during tarball scan: ${err.message}`));
	}

	console.log("");

	if (hasBlocker && !options.force) {
		console.log(
			chalk.red(`🛑 Installation aborted due to critical security findings.`),
		);
		console.log(
			chalk.gray(
				`   Use --force to install anyway if you have verified this package.`,
			),
		);
		process.exit(2);
	}

	// `--dry-run` is checked INDEPENDENTLY of the blocker branch. It previously sat
	// in an `else if`, so `--dry-run --force` on a package with hard blockers fell
	// through and performed a REAL install — the exact combination a user reaches for
	// when they want to inspect a package the tool just flagged.
	if (options.dryRun) {
		if (hasBlocker) {
			console.log(
				chalk.yellow(
					`🚨 Hard blockers found (--force given), but --dry-run takes precedence: nothing was installed.`,
				),
			);
		}
		console.log(chalk.blue(`ℹ️  Dry run completed. No installation performed.`));
		process.exit(hasBlocker ? 2 : hasInfo ? 1 : 0);
	}

	if (hasBlocker && options.force) {
		console.log(
			chalk.yellow(
				`🚨 Hard blockers bypassed due to --force. Proceeding with installation...`,
			),
		);
	}

	console.log(
		chalk.blue(`🔧 Executing npm install (lifecycle scripts disabled)...`),
	);
	try {
		// SECURITY:
		//  - execFileSync with an argv array, never a shell string: pkgName/version
		//    are passed as arguments, so shell metacharacters can't inject commands.
		//  - --ignore-scripts: `npm install` otherwise runs the package's (and every
		//    dependency's) preinstall/postinstall hooks = arbitrary code execution
		//    BEFORE the user ever runs the tool. That directly contradicts the
		//    "checked before anything reaches your terminal" guarantee, so we
		//    neutralize install-time code execution by default.
		const target =
			options.pkgVersion && options.pkgVersion !== "latest"
				? `${pkgName}@${options.pkgVersion}`
				: pkgName;
		// Pin the SAME registry for the install. Without this, `npm install` obeys
		// the ambient npm config while the vet read a different registry — the tool
		// would audit one package and install another.
		const npmArgs = ["install", "--ignore-scripts"];
		if (registry !== DEFAULT_REGISTRY) npmArgs.push("--registry", registry);
		npmArgs.push(target);
		execFileSync("npm", npmArgs, {
			stdio: "inherit",
		});
		console.log(
			chalk.green(
				`\n🎉 Installation complete (install-time scripts were skipped).`,
			),
		);
		if (lifecycleResult.hasScripts) {
			console.log(
				chalk.yellow(
					`   ⚠️  ${pkgName} declares lifecycle scripts (${lifecycleResult.scripts.join(", ")}) that were NOT run. If you trust this package and it needs them, re-run with plain npm.`,
				),
			);
		}
		console.log(`👉 Run 'shield run <script>' to safely execute the agent.`);
		process.exit(hasInfo ? 1 : 0);
	} catch (err: any) {
		console.error(chalk.red(`\n❌ npm install failed.`));
		process.exit(1);
	}
}
