import type { AlertMode, DriftResult } from "./types.js";
import { sanitizeForDisplayInline } from "../../util/untrusted-text.js";

/**
 * Dispatch a drift alert via the configured mode(s).
 */
/**
 * Deliver a drift alert.
 *
 * Returns whether delivery SUCCEEDED. This matters: alerts used to be
 * fire-and-forget — a failed webhook was logged to stderr and the caller advanced
 * its baseline anyway, so the drift was never re-detected and the alert was lost
 * permanently. For a monitoring tool that is the worst possible failure: the one
 * event you needed to hear about is the one that vanished. The caller now holds
 * the baseline back on failure so the same drift is re-reported next cycle.
 */
export async function dispatchAlert(
	drift: DriftResult,
	mode: AlertMode,
	webhookUrl?: string,
): Promise<{ delivered: boolean; error: string | null }> {
	if (mode === "terminal" || mode === "both") {
		renderTerminalAlert(drift);
	}

	if ((mode === "webhook" || mode === "both") && webhookUrl) {
		return await sendWebhookAlert(drift, webhookUrl);
	}

	// Terminal-only delivery is synchronous and cannot fail.
	return { delivered: true, error: null };
}

/**
 * Render a drift alert to the terminal with colored output.
 */
export function renderTerminalAlert(drift: DriftResult): void {
	const divider = "─".repeat(60);
	const timestamp = new Date(drift.timestamp).toLocaleTimeString();

	console.error(`\n${divider}`);
	console.error(`  W.H.Agent Watch — Drift Detected  [${timestamp}]`);
	console.error(divider);

	if (drift.scoreDelta !== 0) {
		const direction = drift.scoreDelta > 0 ? "+" : "";
		const label = drift.scoreDelta > 0 ? "IMPROVED" : "REGRESSED";
		console.error(
			`  Score: ${drift.previousScore} → ${drift.currentScore} (${direction}${drift.scoreDelta}) [${label}]`,
		);
	}

	if (drift.newFindings.length > 0) {
		console.error(`\n  NEW findings (${drift.newFindings.length}):`);
		for (const f of drift.newFindings) {
			const sev = f.severity.toUpperCase().padEnd(8);
			console.error(`    [${sev}] ${sanitizeForDisplayInline(f.title, 200)}`);
			console.error(`             ${sanitizeForDisplayInline(f.file, 200)}`);
		}
	}

	if (drift.resolvedFindings.length > 0) {
		console.error(`\n  RESOLVED findings (${drift.resolvedFindings.length}):`);
		for (const f of drift.resolvedFindings) {
			console.error(`    [RESOLVED] ${f.title}`);
		}
	}

	if (drift.hasCritical) {
		console.error(`\n  *** CRITICAL findings detected ***`);
	}

	console.error(`${divider}\n`);
}

/**
 * Format a drift result as a webhook JSON payload.
 */
export function formatWebhookPayload(drift: DriftResult): string {
	return JSON.stringify({
		event: "wh-agent.drift",
		timestamp: drift.timestamp,
		isRegression: drift.isRegression,
		hasCritical: drift.hasCritical,
		score: {
			previous: drift.previousScore,
			current: drift.currentScore,
			delta: drift.scoreDelta,
		},
		newFindings: drift.newFindings.map((f) => ({
			id: f.id,
			severity: f.severity,
			title: f.title,
			file: f.file,
		})),
		resolvedFindings: drift.resolvedFindings.map((f) => ({
			id: f.id,
			severity: f.severity,
			title: f.title,
			file: f.file,
		})),
	});
}

/**
 * Send a drift alert to a webhook URL.
 */
export async function sendWebhookAlert(
	drift: DriftResult,
	webhookUrl: string,
): Promise<{ delivered: boolean; error: string | null }> {
	const payload = formatWebhookPayload(drift);

	try {
		const response = await fetch(webhookUrl, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: payload,
			signal: AbortSignal.timeout(5000),
		});

		if (!response.ok) {
			const error = `${response.status} ${response.statusText}`;
			console.error(
				`  Webhook alert FAILED: ${error} — this drift will be re-reported on the next scan.`,
			);
			return { delivered: false, error };
		}
		return { delivered: true, error: null };
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.error(
			`  Webhook alert FAILED: ${message} — this drift will be re-reported on the next scan.`,
		);
		return { delivered: false, error: message };
	}
}
