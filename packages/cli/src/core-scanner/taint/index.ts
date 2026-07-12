export { analyzeTaint } from "./analyzer.js";

export function isTaintSupported(filePath: string): boolean {
	return filePath.endsWith(".js") || filePath.endsWith(".ts") || filePath.endsWith(".tsx");
}
