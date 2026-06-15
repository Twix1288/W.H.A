export {
	compareBaseline,
	evaluateGate,
	fingerprintFinding,
	loadBaseline,
	renderComparison,
	renderGateResult,
	saveBaseline,
} from "./compare.js";
export type {
	BaselineComparison,
	GateConfig,
	GateResult,
	SerializedBaseline,
	SerializedFinding,
} from "./types.js";
export { DEFAULT_GATE_CONFIG } from "./types.js";
