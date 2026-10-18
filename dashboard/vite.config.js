import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 3000,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true },
      '/sessions': { target: apiTarget, changeOrigin: true },
      '/events': { target: apiTarget, changeOrigin: true },
      '/reports': { target: apiTarget, changeOrigin: true },
      '/incidents': { target: apiTarget, changeOrigin: true },
      '/ws': { target: apiTarget, changeOrigin: true, ws: true },
    },
  },
})
