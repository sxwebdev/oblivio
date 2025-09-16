import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import pluginReact from "eslint-plugin-react";
import { tanstackConfig } from "@tanstack/eslint-config";
// import tailwind from "eslint-plugin-tailwindcss";
import prettier from "eslint-plugin-prettier/recommended";

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    files: ["**/*.{js,mjs,cjs,ts,jsx,tsx}"],
    plugins: {
      pluginJs,
      pluginReact,
    },
    languageOptions: {
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
      globals: {
        ...globals.browser,
      },
    },
    settings: { react: { version: "19.1" } },
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  pluginReact.configs.flat.recommended,
  pluginReact.configs.flat["jsx-runtime"],
  // ...tailwind.configs["flat/recommended"],
  ...tanstackConfig,
  prettier,
  {
    ignores: ["src/assets/", "src/app/api/gen/", "src/shared/components"],
  },
];
