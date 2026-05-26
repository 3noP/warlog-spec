import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/conformance.ts", "src/cli.ts", "src/verify-cli.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  target: "es2022",
  outDir: "dist",
});
