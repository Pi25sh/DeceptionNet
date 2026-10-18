module.exports = {
  env: {
    browser: true,
    es2021: true,
  },
  ignorePatterns: ['dist', 'node_modules', '*.config.js', 'vite.config.js'],
  extends: [
    'eslint:recommended',
    'plugin:react/recommended',
    'plugin:react-hooks/recommended',
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  plugins: ['react', 'react-hooks'],
  rules: {
    'react/react-in-jsx-scope': 'off',
    'react/prop-types': 'off',
  },
  settings: {
    react: {
      version: '18.2',
    },
  },
};