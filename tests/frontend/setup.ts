import { Window } from "happy-dom";

const win = new Window();
(globalThis as Record<string, unknown>)["globalThis"] = globalThis;

Object.defineProperty(globalThis, "document", {
  value: win.document,
  writable: true,
  configurable: true,
});
Object.defineProperty(globalThis, "window", {
  value: win,
  writable: true,
  configurable: true,
});
Object.defineProperty(globalThis, "URLSearchParams", {
  value: win.URLSearchParams,
  writable: true,
  configurable: true,
});
Object.defineProperty(globalThis, "fetch", {
  value: async () => ({ json: async () => ({}) }),
  writable: true,
  configurable: true,
});
