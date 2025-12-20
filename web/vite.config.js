import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'https://arouter.199028.xyz',
        changeOrigin: true,
        secure: true,
      },
      '/nodes': {
        target: 'https://arouter.199028.xyz',
        changeOrigin: true,
        secure: true,
      },
    }
  },
  build: {
    outDir: '../cmd/controller/web/dist',
    emptyOutDir: true
  }
});
