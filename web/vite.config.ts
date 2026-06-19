import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        // In Docker dev: set API_TARGET=http://server:8000 via environment
        target: process.env.API_TARGET ?? 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
