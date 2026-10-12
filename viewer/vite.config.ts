import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [tailwindcss()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 1024,
  },
  server: { host: "127.0.0.1" },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
  },
});
