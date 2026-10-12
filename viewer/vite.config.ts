import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [tailwindcss()],
  base: "./",
  build: {
    outDir: "../src/appsec_mcp/viewer_dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1024,
  },
  test: {
    environment: "jsdom",
  },
});
