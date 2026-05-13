import path from "node:path"
import { defineConfig } from "vitest/config"

// Test config for the frontend app (not the @oblivio/crypto package — that
// has its own config under packages/crypto). Co-located *.test.ts files in
// src/ are the convention; jsdom gives us crypto.subtle, navigator, etc.
// for the rare test that touches them.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: false,
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test-setup.ts"],
  },
})
