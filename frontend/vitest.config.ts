import { defineConfig } from "vitest/config";

// Frontend tests run in jsdom against a mocked API (src/test/mockApi.ts); no backend needed.
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    testTimeout: 15000,
  },
});
