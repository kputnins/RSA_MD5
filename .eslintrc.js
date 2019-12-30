module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es6: true,
  },
  extends: 'airbnb-base',
  globals: {
    Atomics: 'readonly',
    SharedArrayBuffer: 'readonly',
  },
  parserOptions: {
    ecmaVersion: 2020,
  },
  rules: {
    'arrow-parens': 0,
    'max-len': ['error', { code: 120, tabWidth: 4 }],
    'no-console': 0,
    'no-mixed-operators': 0,
    'no-throw-literal': 0,
  },
};
