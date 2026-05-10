import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    testTimeout: 30_000, // Argon2id is slow even with low params
    coverage: {
      // Plan §13.1: ≥95% lines/statements, ≥90% branches on this package.
      // Coverage is opt-in via `npm run test:coverage`; thresholds here
      // apply unconditionally when enabled. Tweak ONLY upward; lowering on
      // a critical module is a security regression.
      provider: "v8",
      include: ["src/**/*.ts"],
      reporter: ["text", "html", "json-summary"],
      thresholds: {
        lines: 95,
        statements: 95,
        functions: 95,
        branches: 90,
      },
    },
  },
})
