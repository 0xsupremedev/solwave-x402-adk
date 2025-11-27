import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
  },
  // Avoid loading the root PostCSS config when running SDK tests
  css: {
    postcss: {
      plugins: [],
    },
  },
});



