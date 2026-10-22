import crypto from "node:crypto";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// 兼容 Node 16 等旧版本环境中缺少 crypto.getRandomValues 的问题
if (typeof crypto.getRandomValues !== "function") {
  crypto.getRandomValues = (arr) => crypto.randomFillSync(arr);
}

export default defineConfig({
  plugins: [vue()],
  server: {
    host: "0.0.0.0",
    port: 3000,
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_TARGET || "http://127.0.0.1:8080",
        changeOrigin: true,
      },
    },
  },
});

