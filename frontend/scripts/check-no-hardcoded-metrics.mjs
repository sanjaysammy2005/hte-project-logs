// T8.2: charts must be computed from persisted backend data, never from literals in the source.
// Fails if a chart trace uses a literal numeric array, or a metric name is followed by a number.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const patterns = [
  { re: /\b[xyz]\s*:\s*\[\s*-?\d/, why: "literal numeric array in a chart trace" },
  { re: /(detection|false[- ]?positive|localization|accuracy|overhead|rate)[^\n]{0,40}?[:=]\s*-?\d+(\.\d+)?\s*%?/i, why: "metric assigned a literal number" },
  { re: /\b\d+(\.\d+)?\s*%\s*(detection|detected|accuracy|false)/i, why: "literal percentage next to a metric" },
];

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : /\.(tsx?|jsx?)$/.test(name) ? [path] : [];
  });
}

const problems = [];
for (const file of files("src")) {
  readFileSync(file, "utf8").split("\n").forEach((line, i) => {
    for (const { re, why } of patterns) if (re.test(line)) problems.push(`${file}:${i + 1}: ${why}: ${line.trim()}`);
  });
}
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log("check-no-hardcoded-metrics: OK");
