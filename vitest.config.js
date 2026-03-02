import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      include: ['worker/**/*.js'],
      exclude: ['worker/__tests__/**'],
      reporter: ['text', 'html'],
    },
  },
});
