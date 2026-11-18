import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 127.0.0.1 (not "localhost") avoids IPv4/IPv6 mismatches between Vite, Node and Uvicorn.
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, proxy: { "/api": "http://127.0.0.1:8000" } },
});
