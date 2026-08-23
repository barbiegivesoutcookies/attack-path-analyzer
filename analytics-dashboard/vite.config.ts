import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite development configuration. The dev server binds to port 5173, which
// is the exact origin whitelisted in the FastAPI CORS middleware
// (core-engine/main.py), so browser fetches from this dashboard reach the
// backend without cross-origin blocking.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});