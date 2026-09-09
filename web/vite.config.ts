import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { browserLicenseNotices, softwareLicenseText } from './license-notices.mjs'

export default defineConfig({
  plugins: [react(), browserLicenseNotices(), softwareLicenseText()],
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
      '/p': 'http://localhost:8080',
      '/mdq': 'http://localhost:8080',
    },
  },
  test: {
    environment: 'jsdom',
  },
})
