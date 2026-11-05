import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Use no PostCSS plugins here. Without this, Vite walks up the folders and
  // picks up the parent Next.js project's postcss.config.mjs (Tailwind) and fails.
  css: { postcss: {} },
})
