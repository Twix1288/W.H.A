import * as fs from "node:fs";

/**
 * Write a report payload to stdout SYNCHRONOUSLY.
 *
 * WHY THIS EXISTS
 * ---------------
 * `process.exit()` discards pending asynchronous writes. Node writes to a TTY and
 * to a file redirect synchronously, but writes to a PIPE asynchronously — so a
 * command that did:
 *
 *     console.log(sarifJson);
 *     process.exit(code);
 *
 * silently truncated its own output at the pipe buffer (~8KB) whenever the
 * consumer was another process. Running it by hand in a terminal, or with
 * `> file.json`, looked perfect; captured by a CI step, a GitHub Action, or any
 * wrapper that spawns the CLI and reads stdout, the JSON/SARIF came back cut
 * mid-token and unparseable. That is the single most common way this tool is
 * consumed, and the failure is invisible to the person who shipped it.
 *
 * fs.writeSync(1, …) cannot be discarded by process.exit(). The retry loop covers
 * partial writes and EAGAIN, which a non-blocking pipe will return under load.
 */
export function writeStdoutSync(text: string): void {
	const payload = text.endsWith("\n") ? text : `${text}\n`;
	const buf = Buffer.from(payload, "utf8");
	let offset = 0;
	while (offset < buf.length) {
		try {
			offset += fs.writeSync(1, buf, offset, buf.length - offset);
		} catch (err) {
			const code = (err as NodeJS.ErrnoException).code;
			// A non-blocking pipe that is momentarily full: retry rather than lose
			// the remainder of the report.
			if (code === "EAGAIN") continue;
			// EPIPE means the consumer closed early (e.g. `| head`). That is not an
			// error worth crashing over — stop writing.
			if (code === "EPIPE") return;
			throw err;
		}
	}
}
