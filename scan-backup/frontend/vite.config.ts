import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    lib: {
      entry: 'src/index.ts',
      formats: ['umd'],
      name: 'RedopsModule_scan-backup',
      fileName: () => 'frontend.js',
    },
    rollupOptions: {
      external: ['vue'],
      output: { globals: { vue: 'Vue' } },
    },
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
})
