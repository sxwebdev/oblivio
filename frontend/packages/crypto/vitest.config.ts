import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    testTimeout: 30_000, // Argon2id is slow even with low params
  },
})
