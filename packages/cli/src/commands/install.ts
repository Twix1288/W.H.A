import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as https from "node:https";
import * as os from "node:os";
import * as path from "node:path";
import chalk from "chalk";
import * as tar from "tar";

interface InstallOptions {
	force: boolean;
	dryRun: boolean;
	pkgVersion?: string;
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

function fetchPackageMetadata(
	packageName: string,
	version = "latest",
): Promise<any> {
	return new Promise((resolve, reject) => {
		const req = https.get(
			`https://registry.npmjs.org/${packageName}`,
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

function checkTyposquat(packageName: string) {
	let popularPackages: string[] = [];
	try {
		popularPackages = require("./popular-packages.json");
	} catch (err) {
		// silently ignore if the static list is missing
		return { risky: false, similarTo: [] };
	}

	const close = popularPackages.filter((p) => {
		if (p === packageName) return false;
		const dist = levenshtein(p, packageName);
		return (
			dist > 0 && dist <= 2 && Math.abs(p.length - packageName.length) <= 2
		);
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
		found.forEach((s) => console.log(chalk.gray(`   ${s}: ${scripts[s]}`)));
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

const SECRET_PATTERNS = [
	{ name: "AWS Access Key", re: /AKIA[0-9A-Z]{16}/ },
	{ name: "Private Key", re: /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/ },
	{
		name: "Generic API Key assignment",
		re: /api[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/i,
	},
	{
		name: "eval of remote content",
		re: /eval\(\s*(await\s+)?fetch|eval\(.*http/i,
	},
];

async function scanTarball(packageName: string, manifest: any) {
	const tarballUrl = manifest.dist?.tarball;
	if (!tarballUrl) {
		console.log(chalk.gray(`ℹ️  No tarball URL found in manifest.`));
		return { findings: [], binaries: [] };
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
			return { findings: [], binaries: [] };
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
		return { findings: [{ file: "tarball", pattern: "Extraction failure" }], binaries: [] };
	}

	const findings: { file: string; pattern: string; redacted: string }[] = [];
	const binaries: string[] = [];

	function walk(dir: string) {
		const entries = fs.readdirSync(dir);
		for (const f of entries) {
			const full = path.join(dir, f);
			const stat = fs.statSync(full);
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
				binaries.push(`${relativePath} (Large blob: ${Math.round(stat.size/1024/1024)}MB)`);
				continue;
			}

			if (!/\.(js|ts|json)$/.test(f)) continue;

			const content = fs.readFileSync(full, "utf-8");
			for (const { name, re } of SECRET_PATTERNS) {
				const match = content.match(re);
				if (match) {
					// match[1] is the captured group if any, otherwise match[0]
					const secret = match[1] || match[0];
					const redacted = secret.length > 8 ? secret.slice(0, 4) + "***" : "***";
					findings.push({ file: relativePath, pattern: name, redacted });
				}
			}
		}
	}

	try {
		walk(tmpDir);
	} catch (e) {
		// Ignore walk errors
	}

	fs.rmSync(tmpDir, { recursive: true, force: true });

	if (findings.length > 0) {
		console.log(chalk.red(`⚠️  Suspicious patterns found in package source:`));
		findings.forEach((f) =>
			console.log(chalk.red(`   ${f.file}: ${f.pattern} (${f.redacted})`)),
		);
	} else {
		console.log(chalk.green(`✅ No known suspicious patterns found in source.`));
	}

	if (binaries.length > 0) {
		console.log(
			chalk.yellow(
				`ℹ️  This package ships native binaries or large blobs which were not scanned:\n   ${binaries.join("\n   ")}`,
			),
		);
	}

	return { findings, binaries };
}

export async function installAgent(pkgName: string, options: InstallOptions) {
	console.log(`\n📦 W.H.Agent Supply Chain: Checking ${pkgName}`);

	let hasBlocker = false;
	let hasInfo = false;

	// 1. Typosquat Check
	const typoResult = checkTyposquat(pkgName);
	if (typoResult.risky) hasBlocker = true;

	let manifest;
	try {
		manifest = await fetchPackageMetadata(pkgName, options.pkgVersion || "latest");
	} catch (err: any) {
		if (err.message === "PACKAGE_NOT_FOUND") {
			console.error(chalk.red(`❌ Package '${pkgName}' not found on npm.`));
		} else if (err.message === "TIMEOUT") {
			console.error(chalk.red(`❌ Registry request timed out.`));
		} else {
			console.error(chalk.red(`❌ Failed to fetch package metadata: ${err.message}`));
		}
		process.exit(1);
	}

	// 2. Lifecycle Scripts Check
	const lifecycleResult = checkLifecycleScripts(pkgName, manifest);
	if (lifecycleResult.hasScripts) hasInfo = true;

	// 3. Provenance Check
	checkProvenance(pkgName, manifest);

	// 4. Tarball Scan
	let tarballResult;
	try {
		tarballResult = await scanTarball(pkgName, manifest);
		if (tarballResult.findings.length > 0) hasBlocker = true;
		if (tarballResult.binaries.length > 0) hasInfo = true;
	} catch (err: any) {
		console.log(chalk.red(`⚠️  Error during tarball scan: ${err.message}`));
	}

	console.log("");

	if (hasBlocker) {
		if (options.force) {
			console.log(chalk.yellow(`🚨 Hard blockers bypassed due to --force. Proceeding with installation...`));
		} else {
			console.log(chalk.red(`🛑 Installation aborted due to critical security findings.`));
			console.log(chalk.gray(`   Use --force to install anyway if you have verified this package.`));
			process.exit(2);
		}
	} else if (options.dryRun) {
		console.log(chalk.blue(`ℹ️  Dry run completed. No installation performed.`));
		process.exit(hasInfo ? 1 : 0);
	}

	console.log(chalk.blue(`🔧 Executing npm install...`));
	try {
		execSync(`npm install ${pkgName}${options.pkgVersion && options.pkgVersion !== 'latest' ? `@${options.pkgVersion}` : ''}`, { stdio: "inherit" });
		console.log(chalk.green(`\n🎉 Installation safe and complete.`));
		console.log(`👉 Run 'shield run <script>' to safely execute the agent.`);
		process.exit(hasInfo ? 1 : 0);
	} catch (err: any) {
		console.error(chalk.red(`\n❌ npm install failed.`));
		process.exit(1);
	}
}
