import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);
const output = path.resolve(process.argv[2] ?? "reports/security/local");
fs.mkdirSync(output, { recursive: true });
const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const write = (name, value) => fs.writeFileSync(path.join(output, name), JSON.stringify(value, null, 2) + "\n");
const versions = { gosec: "2.30.0", gitleaks: "8.30.1", eslint: "10.15.0", parser: "8.72.2", security_plugin: "4.2.1" };
const executables = { gosec: process.env.GOSEC_BIN ?? "gosec", gitleaks: process.env.GITLEAKS_BIN ?? "gitleaks" };
function run(name, executable, args, accepted = [0]) {
  const result = spawnSync(executable, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, windowsHide: true });
  // Gitleaks console output is never persisted: only its --redact=100 JSON report is saved.
  if (name !== "gitleaks") fs.writeFileSync(path.join(output, `${name}.log`), (result.stdout ?? "") + (result.stderr ?? ""));
  if (result.error || !accepted.includes(result.status)) throw new Error(`${name} failed: ${result.error?.message ?? `exit ${result.status}`}`);
  // Gitleaks can log Git errors while returning 0. Scans run at error log level without a banner.
  if (name === "gitleaks" && result.stderr?.trim()) throw new Error("gitleaks reported a scan error");
  return { command: [executable, ...args], exit_code: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}
const sourceFiles = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
  .filter(file => file && !file.startsWith("reports/security/") && !path.resolve(file).startsWith(output + path.sep));
const files = Object.fromEntries([...new Set(sourceFiles)].sort().filter(file => fs.existsSync(file)).map(file =>
  [file, createHash("sha256").update(fs.readFileSync(file)).digest("hex")]));
const manifest = {
  checked_commit: git("rev-parse", "HEAD"),
  working_tree: git("status", "--porcelain=v1"),
  source_sha256: files,
  refs: git("for-each-ref", "--format=%(refname) %(objectname)"),
  history_commits: Number(git("rev-list", "--all", "--count")),
  shallow: git("rev-parse", "--is-shallow-repository") === "true",
  started_at: new Date().toISOString(), versions, platform: `${os.platform()}/${os.arch()}`, commands: {},
  runtimes: { node: process.version, go: execFileSync("go", ["version"], { encoding: "utf8" }).trim() },
  github_run_id: process.env.GITHUB_RUN_ID ?? null,
  github_run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
};
write("source.json", manifest);
let tree;
try {
  for (const tool of ["gosec", "gitleaks"]) {
    const version = run(`${tool}-version`, executables[tool], [tool === "gosec" ? "-version" : "version"]);
    if (!(version.stdout + version.stderr).includes(versions[tool])) {
      const build = run(`${tool}-build`, "go", ["version", "-m", executables[tool]]);
      if (tool !== "gosec" || !build.stdout.includes(`github.com/securego/gosec/v2\tv${versions.gosec}`)) throw new Error(`Expected ${tool} ${versions[tool]}`);
    }
  }
  const eslintPackage = JSON.parse(fs.readFileSync("node_modules/eslint/package.json", "utf8"));
  if (eslintPackage.version !== versions.eslint) throw new Error(`Expected ESLint ${versions.eslint}`);
  for (const [name, version] of [["@typescript-eslint/parser", versions.parser], ["eslint-plugin-security", versions.security_plugin]]) {
    if (JSON.parse(fs.readFileSync(`node_modules/${name}/package.json`, "utf8")).version !== version) throw new Error(`Expected ${name} ${version}`);
  }
  const gosec = run("gosec", executables.gosec, ["-fmt=json", `-out=${path.join(output, "gosec.json")}`, "./cmd/...", "./internal/...", "./web/..."], [0, 1]);
  manifest.commands.gosec = { ...gosec, stdout: undefined, stderr: undefined };
  const eslint = run("eslint", process.execPath, ["node_modules/eslint/bin/eslint.js", "--config", "eslint.security.config.mjs", "web/src", "--format", "json", "--output-file", path.join(output, "eslint.json")], [0, 1]);
  manifest.commands.eslint = { ...eslint, stdout: undefined, stderr: undefined };
  if (manifest.shallow) throw new Error("History scan requires a full clone (CI: fetch-depth: 0)");
  const secretFlags = ["--config=.gitleaks.toml", "--redact=100", "--exit-code=10", "--no-banner", "--no-color", "--log-level=error"];
  const history = run("gitleaks", executables.gitleaks, ["git", ...secretFlags, "--log-opts=--all", "--report-format=json", `--report-path=${path.join(output, "gitleaks-history.json")}`, "."], [0, 10]);
  manifest.commands.history = { ...history, stdout: undefined, stderr: undefined };
  // Only versioned / non-ignored project files; ignored local .env and dependencies stay outside.
  tree = fs.mkdtempSync(path.join(os.tmpdir(), "kozyrniytuz-secrets-"));
  for (const file of Object.keys(files)) {
    const target = path.join(tree, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, file), target);
  }
  const current = run("gitleaks", executables.gitleaks, ["dir", ...secretFlags, "--report-format=json", `--report-path=${path.join(output, "gitleaks-tree.json")}`, tree], [0, 10]);
  manifest.commands.tree = { ...current, stdout: undefined, stderr: undefined };
  const go = JSON.parse(fs.readFileSync(path.join(output, "gosec.json"), "utf8"));
  const js = JSON.parse(fs.readFileSync(path.join(output, "eslint.json"), "utf8"));
  const count = name => JSON.parse(fs.readFileSync(path.join(output, name), "utf8")).length;
  if (!go.Stats?.files || !js.length) throw new Error("Analyzer returned an empty source scope");
  if (Object.keys(go["Golang errors"] ?? {}).length || js.some(file => file.fatalErrorCount)) throw new Error("Analyzer parse/type errors: scan is incomplete");
  manifest.results = { gosec: (go.Issues ?? []).length, eslint: js.reduce((sum, file) => sum + file.messages.length, 0), secrets_history: count("gitleaks-history.json"), secrets_tree: count("gitleaks-tree.json") };
  manifest.complete = true;
  const reviewed = JSON.parse(fs.readFileSync("security-reviewed.json", "utf8"));
  const fingerprint = (tool, rule, file, line) => {
    const relative = path.relative(root, file).replaceAll("\\", "/");
    const source = fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");
    const lineNumber = Number(String(line).split("-")[0]);
    const content = source.split("\n")[lineNumber - 1]?.trim();
    return { tool, rule, file: relative, line: lineNumber, source_sha256: createHash("sha256").update(content ?? "").digest("hex"), file_lf_sha256: createHash("sha256").update(source).digest("hex") };
  };
  const signals = [
    ...(go.Issues ?? []).map(issue => fingerprint("gosec", issue.rule_id, issue.file, issue.line)),
    ...js.flatMap(file => file.messages.map(message => fingerprint("eslint", message.ruleId, file.filePath, message.line))),
  ];
  manifest.signals = signals;
  manifest.unreviewed = signals.filter(signal => !reviewed.some(item => item.tool === signal.tool && item.rule === signal.rule && item.file === signal.file && item.line === signal.line && item.source_sha256 === signal.source_sha256 && item.file_lf_sha256 === signal.file_lf_sha256 && item.decision && item.reason));
  // Secret findings always require investigation; they cannot be waived by this SAST registry.
  if (manifest.unreviewed.length || manifest.results.secrets_history || manifest.results.secrets_tree) process.exitCode = 1;
  console.log(JSON.stringify(manifest.results));
} catch (error) {
  manifest.complete = false;
  manifest.error = error.message;
  process.exitCode = 2;
  console.error(error.message);
} finally {
  manifest.finished_at = new Date().toISOString();
  manifest.exit_code = process.exitCode ?? 0;
  manifest.reports_sha256 = Object.fromEntries(["gosec.json", "eslint.json", "gitleaks-history.json", "gitleaks-tree.json"]
    .filter(file => fs.existsSync(path.join(output, file)))
    .map(file => [file, createHash("sha256").update(fs.readFileSync(path.join(output, file))).digest("hex")]));
  write("source.json", manifest);
  // Files are ordinary copied project files in our freshly created temporary directory.
  if (tree && path.dirname(tree) === os.tmpdir() && path.basename(tree).startsWith("kozyrniytuz-secrets-")) fs.rmSync(tree, { recursive: true });
}
