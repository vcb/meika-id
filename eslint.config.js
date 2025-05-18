const {
    defineConfig,
} = require("eslint/config");

const sonarjs = require("eslint-plugin-sonarjs");
const tsParser = require("@typescript-eslint/parser");
const js = require("@eslint/js");

const {
    FlatCompat,
} = require("@eslint/eslintrc");

const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

module.exports = defineConfig([{
    ignores: [
        "**/node_modules/**",
        "**/.next/**",
        "**/.env",
        "**/.env.local",
        "**/.env.development.local",
        "**/.env.test.local",
        "**/.env.production.local",
        "**/*.json",
        "**/*.zkey",
        "**/*.wasm",
        "**/build/**",
    ],
}, {
    plugins: {
        sonarjs,
    },

    rules: {
        ...sonarjs.configs.recommended.rules
    },
}, {
    files: ["**/*.ts", "**/*.tsx"],

    languageOptions: {
        parser: tsParser,
        sourceType: "module",

        parserOptions: {
            project: ["./tsconfig.base.json"],
        },
    },

    plugins: {
        "@typescript-eslint": require("@typescript-eslint/eslint-plugin"),
        sonarjs,
    },

    rules: {
        ...sonarjs.configs.recommended.rules,
        ...require("@typescript-eslint/eslint-plugin").configs.recommended.rules,
    }
}]);