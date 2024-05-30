import path from "path";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import url from "@rollup/plugin-url";
// import { terser } from "rollup-plugin-terser";
import analyzer from "rollup-plugin-analyzer";
import copy from "rollup-plugin-copy";
import alias from "@rollup/plugin-alias";

const production = process.env.NODE_ENV === "production";
const dir = "lib";
const input = "src/index.ts";

const plugins = [
  alias({
    entries: [
      {
        find: "@libdemos",
        replacement: path.join(process.cwd(), "wasm", "libdemos"),
      },
    ],
  }),

  replace({
    preventAssignment: true,
    "process.env.NODE_ENV": JSON.stringify(production),
  }),

  resolve({
    // jsnext: true,
    // main: true,
    // module: true,
    browser: true,
    preferBuiltins: false,
  }),

  commonjs(),

  url(),

  json({
    compact: true,
    preferConst: true,
  }),

  typescript({
    sourceMap: true,
    inlineSources: !production,
    declaration: true,
    declarationMap: true,
    exclude: [
      `__tests__`,
      `__tests__${path.sep}*.test.{j,t}s`,
      `__spec__`,
      `__spec__${path.sep}*.spec.{j,t}s`,
      "playwright*",
      "rollup*",
    ],
    paths: {
      "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
    },
    outDir: `${dir}`,
  }),

  // !browser &&
  copy({
    targets: [
      {
        src: path.join(process.cwd(), "wasm"),
        dest: `${dir}`,
      },
    ],
  }),

  analyzer(),
];

export default [
  // UMD
  {
    input,
    plugins,
    output: {
      name: "ondemos",
      file: `lib${path.sep}index.min.js`,
      format: "umd",
      esModule: false,
      interop: "default",
      extend: true,
      sourcemap: true,
      paths: {
        "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
      },
    },
  },

  // ESM and CJS
  {
    input,
    plugins,
    external: ["module"],
    output: [
      {
        file: `lib${path.sep}index.mjs`,
        format: "es",
        esModule: true,
        interop: "esModule",
        exports: "named",
        sourcemap: true,
        paths: {
          "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
        },
      },
      {
        file: `lib${path.sep}index.js`,
        format: "cjs",
        esModule: false,
        interop: "defaultOnly",
        exports: "default",
        sourcemap: true,
        paths: {
          "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
        },
      },
    ],
  },
];
