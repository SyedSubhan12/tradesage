import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: true,
    port: 8080,
    open: true, // Auto-open browser
    strictPort: true, // Don't try other ports if 8080 is in use
    proxy: {
      // Proxy API requests to backend
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '')
      },
      // Proxy OAuth login/register endpoints
      '/oauth': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false
      }
    }
  },
  plugins: [
    react(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // Force CSS to be visible
  css: {
    devSourcemap: true,
  },
  // Define environment variables
  define: {
    // This replaces process.env in the code
    'import.meta.env.VITE_API_URL': JSON.stringify('/api'),
  },
}));
