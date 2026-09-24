import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

export default tseslint.config(
  // 构建产物与依赖不参与检查
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    rules: {
      // Hooks 的两条经典规则：rules-of-hooks 是硬性正确性要求，
      // exhaustive-deps 提示依赖缺失（源码里已有的 eslint-disable 注释正是针对它）。
      //
      // 有意不启用 react-hooks 7.x 新增的 React Compiler 系列规则
      // （set-state-in-effect / no-deriving-state-in-effect 等）：它们会对存量写法
      // 大面积报错，需要专门排期整改，不适合与本次检查一并引入。
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // 未使用变量：允许以 _ 开头的占位（事件回调、有意忽略的参数等）
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      // 显式 any 在 API 边界层（api.ts / api-types.ts）是有意为之，降为警告
      '@typescript-eslint/no-explicit-any': 'warn',
      // 空对象类型在第三方 shim 里常见
      '@typescript-eslint/no-empty-object-type': 'off',
    },
  },
)
