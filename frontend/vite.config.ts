import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In Docker, /api is proxied to the backend service; locally it defaults to localhost:8000.
const apiTarget = process.env.VITE_API_PROXY_TARGET ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  // Plotly (~1.2 MB) is split into the lazily loaded Experiments page chunk on purpose.
  build: { chunkSizeWarningLimit: 1300 },
  server: {
    port: 5173,
    // File-change events do not cross Windows bind mounts; poll instead when running in Docker.
    watch: { usePolling: process.env.VITE_USE_POLLING === "true" },
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
    },
  },
});
