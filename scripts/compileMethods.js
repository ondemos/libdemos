const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const {
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  emcc,
} = require("./utils.js");

const basePath = path.join(process.cwd(), "..", "libdemos", "src");
const buildPath = path.join(process.cwd(), "build");
if (fs.existsSync(buildPath))
  fs.rmSync(buildPath, { recursive: true, force: true });
fs.mkdirSync(buildPath);

const methodsPath = path.join(basePath, "demos.c");
const wasmPath = path.join(buildPath, "demosMethodsModule.js");

const typesPath = path.join(
  process.cwd(),
  "scripts",
  "demosMethodsModule.d.ts",
);
const types = fs.readFileSync(typesPath);
fs.writeFileSync(wasmPath.replace("le.js", "le.d.ts"), types);

const testing =
  process.env.NODE_ENV === "production"
    ? `\
-flto \
-Os \
-s FILESYSTEM=0 \
-s ASSERTIONS=0 \
-s INVOKE_RUN=0 \
`
    : `\
-O0 \
-g3 \
--profiling \
-gsource-map \
-fsanitize=undefined \
-s ASSERTIONS=2 \
-s RUNTIME_LOGGING=1 \
-s RUNTIME_DEBUG=1 \
-s SAFE_HEAP=2 \
-s STACK_OVERFLOW_CHECK=2 \
-s EXIT_RUNTIME=1 \
`;

execSync(
  `\
${emcc} \
${testing} \
-s EXPORTED_FUNCTIONS=\
_malloc,\
_free,\
_generate_identities,\
_commitment_update_irreversible,\
_commitment_update_reversible,\
_generate_proof,\
_verify_proof \
-s EXPORT_NAME=demosMethodsModule \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${wasmPath} \
${methodsPath}`,
  { stdio: "inherit" },
);

let content = fs.readFileSync(wasmPath, "utf8");
fs.writeFileSync(
  wasmPath,
  "'use strict'" + content.replace('"use strict"', ""),
);

console.log("Successfully compiled libdemos c methods to Wasm.");
