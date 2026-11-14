import parser from "@typescript-eslint/parser";
import security from "eslint-plugin-security";

export default [
  {
    files: ["web/src/**/*.ts"],
    languageOptions: { parser },
    plugins: { security },
    rules: {
      ...security.configs.recommended.rules,
      "no-restricted-syntax": ["error",
        { selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]", message: "Use textContent or DOM nodes for untrusted text; review HTML parsing explicitly." },
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "Review HTML parsing of untrusted content." },
        { selector: "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]", message: "Use DOM nodes instead of document.write." },
        { selector: "NewExpression[callee.name='Function']", message: "Do not compile untrusted text as JavaScript." },
      ],
    },
  },
];
