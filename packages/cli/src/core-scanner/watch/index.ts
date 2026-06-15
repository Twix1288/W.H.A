export {
	dispatchAlert,
	formatWebhookPayload,
	renderTerminalAlert,
	sendWebhookAlert,
} from "./alerts.js";
export { createBaseline, diffBaseline, fingerprintFinding } from "./diff.js";
export type {
	AlertMode,
	DriftResult,
	ScanBaseline,
	WatchConfig,
	WatchEvent,
	WatcherState,
} from "./types.js";
export { startWatcher } from "./watcher.js";
