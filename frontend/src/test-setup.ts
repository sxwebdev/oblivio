// Vitest setup for the frontend test runner.
//
// vitest 4 + jsdom does not always wire `localStorage` onto the global
// when the module under test pulls in zustand `persist`. Our auth store
// reads `localStorage.getItem` at module-init time (see
// stores/auth.ts:32), so we shim a minimal in-memory store before any
// test file imports run.

class MemStorage implements Storage {
  private data = new Map<string, string>()
  get length() {
    return this.data.size
  }
  clear() {
    this.data.clear()
  }
  getItem(key: string) {
    return this.data.get(key) ?? null
  }
  key(index: number) {
    return Array.from(this.data.keys())[index] ?? null
  }
  removeItem(key: string) {
    this.data.delete(key)
  }
  setItem(key: string, value: string) {
    this.data.set(key, value)
  }
}

if (typeof globalThis.localStorage === "undefined") {
  Object.defineProperty(globalThis, "localStorage", {
    value: new MemStorage(),
    configurable: true,
  })
}
if (typeof globalThis.sessionStorage === "undefined") {
  Object.defineProperty(globalThis, "sessionStorage", {
    value: new MemStorage(),
    configurable: true,
  })
}
