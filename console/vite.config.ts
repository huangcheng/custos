import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Dev: proxy the API and the MCP transport to a locally running server.
// Prod: dist/ is served same-origin by the app (custos/console.py).
const target = process.env.CUSTOS_DEV_URL ?? "http://127.0.0.1:8300";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: {
      "/api": { target, changeOrigin: false },
      "/mcp": { target, changeOrigin: false },
      "/healthz": { target, changeOrigin: false },
    },
  },
});
