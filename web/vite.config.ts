import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/v1': {
        target: 'http://192.168.8.92:3000',
        changeOrigin: true,
      },
      '/health': {
        target: 'http://192.168.8.92:3000',
        changeOrigin: true,
      },
      '/ready': {
        target: 'http://192.168.8.92:3000',
        changeOrigin: true,
      },
    },
  },
});
