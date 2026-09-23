// Standalone flat config (ESLint 9+) for this package. Previously this
// SDK had no config of its own and relied on eslint's directory walk-up
// finding avalon-protocol's root config by accident (bindings/ts's parent
// was that repo's root) — not something to rely on once this package
// isn't nested under that repo at all.
import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import globals from 'globals'

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{js,mjs,cjs,ts}'],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },
)
