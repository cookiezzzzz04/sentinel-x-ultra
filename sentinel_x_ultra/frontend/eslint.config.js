/**
 * ESLint Flat Config — Sentinel-X Ultra Frontend
 *
 * ESLint v10 flat config with Prettier integration.
 * Run with: npx eslint src/
 * Fix with: npx eslint src/ --fix
 */

import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';
import reactHooks from 'eslint-plugin-react-hooks';
import eslintPluginPrettier from 'eslint-plugin-prettier';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', '*.config.*'],
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
      'react-hooks': reactHooks,
      prettier: eslintPluginPrettier,
    },
    rules: {
      // TypeScript
      ...tseslint.configs['recommended'].rules,
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
      '@typescript-eslint/consistent-type-imports': 'warn',

      // React Hooks
      ...reactHooks.configs.recommended.rules,
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // Prettier — runs as an ESLint rule, auto-formats on --fix
      'prettier/prettier': ['warn', {
        semi: true,
        singleQuote: true,
        trailingComma: 'all',
        printWidth: 100,
        tabWidth: 2,
        arrowParens: 'always',
        bracketSpacing: true,
        endOfLine: 'lf',
      }],

      // General
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': ['error', 'always'],
      'curly': ['error', 'all'],
    },
  },
];
