/**
 * Handling for text that came from a scanned file, an MCP server, or any other
 * place an attacker controls.
 *
 * Two distinct jobs, deliberately kept separate because conflating them is how
 * scanners get bypassed:
 *
 *  - `sanitizeForDisplay` — make attacker text SAFE TO PRINT. Used on every path
 *    that renders untrusted content to a terminal, a markdown file or a report.
 *  - `normalizeForMatching` — make attacker text HONEST TO MATCH AGAINST. Used
 *    before running detection patterns, so invisible characters cannot split a
 *    keyword in half.
 *
 * Never use the matching form for display (it destroys evidence) and never use
 * the display form for matching (it does not remove zero-width splitters).
 */

// ─── Display ──────────────────────────────────────────────────────────────────
//
// A finding's "evidence" is a verbatim excerpt of attacker-controlled content. It
// was printed raw, so a scanned repository could embed ANSI escapes and carriage
// returns in its own config and rewrite the report describing it — erasing its
// CRITICAL findings from the terminal, or forging a clean summary. The report is
// the one artifact a security tool must not let the subject of the report edit.

// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the entire point
const ANSI_CSI = /\x1b\[[0-?]*[ -\/]*[@-~]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: see above
const ANSI_OSC = /\x1b\][\s\S]*?(?:\x07|\x1b\\)/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: see above
const ANSI_SINGLE = /\x1b[@-Z\\-_]/g;
// C0 controls except tab, plus DEL and C1 controls. \r is included: a lone
// carriage return rewrites the current terminal line.
// biome-ignore lint/suspicious/noControlCharactersInRegex: see above
const CONTROL_CHARS = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;

/**
 * Render untrusted text safely for a terminal or a report.
 *
 * Escape sequences and control characters are replaced with a visible marker
 * rather than dropped, so the reader can see that something was there — hiding
 * the evidence of an injection attempt would be its own kind of lie.
 */
export function sanitizeForDisplay(input: string, maxLength = 2000): string {
	const stripped = input
		.replace(ANSI_OSC, "␛")
		.replace(ANSI_CSI, "␛")
		.replace(ANSI_SINGLE, "␛")
		.replace(/\r\n?/g, "\n")
		.replace(CONTROL_CHARS, "�");

	// Collapse to a single line for one-line report contexts is the caller's job;
	// here we only bound the length so a multi-megabyte "evidence" string cannot
	// flood the terminal.
	if (stripped.length <= maxLength) return stripped;
	return `${stripped.slice(0, maxLength)}… [truncated ${stripped.length - maxLength} chars]`;
}

/** Single-line variant for table cells and one-line summaries. */
export function sanitizeForDisplayInline(input: string, maxLength = 300): string {
	return sanitizeForDisplay(input, maxLength).replace(/\n+/g, " ⏎ ");
}

/**
 * Escape untrusted text for embedding in a Markdown document.
 *
 * The markdown reporter interpolated findings directly, so a scanned repo could
 * emit its own headings, tables and raw HTML into the report — including an
 * `<img src=x onerror=...>` if the markdown is later rendered, or a fake
 * "## No issues found" section.
 */
export function escapeMarkdown(input: string): string {
	return sanitizeForDisplayInline(input)
		.replace(/[\\`*_{}[\]()#+\-.!|<>]/g, (c) => `\\${c}`)
		.replace(/\n/g, " ");
}

// ─── Matching ─────────────────────────────────────────────────────────────────
//
// Prompt-injection and tool-poisoning rules match on words like "ignore",
// "IMPORTANT", "id_rsa". An LLM reading an MCP tool description ignores
// zero-width characters entirely, but a regex does not: inserting U+200B inside
// "read" defeats every keyword rule while the instruction still reaches the model
// verbatim. The Unicode TAG block (U+E0000–U+E007F) is worse — it encodes a full
// ASCII message that is completely invisible in every editor and terminal.

/**
 * Format characters and zero-width joiners/spaces that split words invisibly.
 *
 * Built as an ALTERNATION rather than one character class: some of these are
 * combining characters, and a class that mixes a base character with a combining
 * one can match a grapheme the author did not intend.
 */
const INVISIBLE_CHARS = new RegExp(
	[
		"\\u00ad", // soft hyphen
		"\\u034f", // combining grapheme joiner
		"\\u061c", // arabic letter mark
		"\\u115f", // hangul choseong filler
		"\\u1160", // hangul jungseong filler
		"\\u17b4", // khmer vowel inherent aq
		"\\u17b5", // khmer vowel inherent aa
		"[\\u180b-\\u180e]", // mongolian selectors + vowel separator
		"[\\u200b-\\u200f]", // zero-width space/joiners, LTR/RTL marks
		"[\\u202a-\\u202e]", // bidirectional embedding/override
		"[\\u2060-\\u206f]", // word joiner, invisible operators, deprecated formats
		"\\u3164", // hangul filler
		"[\\ufe00-\\ufe0f]", // variation selectors
		"\\ufeff", // zero-width no-break space (BOM)
		"\\uffa0", // halfwidth hangul filler
	].join("|"),
	"gu",
);

/**
 * Fold attacker text into the form a language model effectively sees, so
 * detection patterns match what will actually be acted on.
 *
 * - Unicode TAG characters are mapped back to the ASCII they encode.
 * - Zero-width and bidirectional-control characters are removed.
 * - NFKC folds compatibility variants (fullwidth, styled maths letters) to ASCII.
 */
export function normalizeForMatching(input: string): string {
	// Map the invisible TAG block back to the ASCII it stands for. These are the
	// payload of the "invisible instructions" technique.
	const detagged = input.replace(/[\u{E0020}-\u{E007E}]/gu, (ch) =>
		String.fromCharCode((ch.codePointAt(0) as number) - 0xe0000),
	);
	// Drop the TAG delimiters themselves.
	const withoutTagMarks = detagged.replace(/[\u{E0001}\u{E007F}]/gu, "");
	return withoutTagMarks.normalize("NFKC").replace(INVISIBLE_CHARS, "");
}

/**
 * True when text contains characters that are invisible to a human reviewer but
 * meaningful to a model. Worth reporting in its own right: legitimate config
 * almost never contains them, and their presence in a tool description is a
 * deliberate concealment attempt.
 */
export function hasInvisibleCharacters(input: string): boolean {
	if (/[\u{E0000}-\u{E007F}]/u.test(input)) return true;
	INVISIBLE_CHARS.lastIndex = 0;
	return INVISIBLE_CHARS.test(input);
}

/** Human-readable names for the invisible characters present, for the finding text. */
export function describeInvisibleCharacters(input: string): string {
	const found = new Set<string>();
	if (/[\u{E0000}-\u{E007F}]/u.test(input)) found.add("Unicode TAG block (invisible ASCII)");
	if (/[\u200b-\u200d\ufeff]/u.test(input)) found.add("zero-width characters");
	if (/[\u202a-\u202e\u061c]/u.test(input)) found.add("bidirectional overrides");
	if (/[\u2060-\u206f]/u.test(input)) found.add("word-joiner / invisible operators");
	if (/\u00ad/u.test(input)) found.add("soft hyphens");
	return [...found].join(", ") || "invisible characters";
}
