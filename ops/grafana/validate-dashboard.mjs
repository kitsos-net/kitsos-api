import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dashboard = JSON.parse(
  readFileSync(join(here, "dashboards", "kitsos-platform-overview.json"), "utf8"),
);

const expectedDatasourceUids = new Set(["kitsos-analytics-api", "kitsos-axiom"]);
const ids = new Set();
const problems = [];

if (dashboard.uid !== "kitsos-platform-overview") problems.push("unexpected dashboard UID");
if (!Array.isArray(dashboard.panels) || dashboard.panels.length < 10) {
  problems.push("dashboard must contain at least 10 panels");
}

for (const panel of dashboard.panels ?? []) {
  if (ids.has(panel.id)) problems.push(`duplicate panel id ${panel.id}`);
  ids.add(panel.id);
  if (!panel.title || !panel.gridPos) problems.push(`panel ${panel.id} is incomplete`);

  for (const target of panel.targets ?? []) {
    if (!expectedDatasourceUids.has(target.datasource?.uid)) {
      problems.push(`panel ${panel.id} has unknown datasource`);
    }
    if (JSON.stringify(target).includes("YOUR_")) {
      problems.push(`panel ${panel.id} contains a placeholder`);
    }
  }
}

const serialized = JSON.stringify(dashboard);
for (const forbidden of ["kitsos_", "cfut_", "Bearer ey"]) {
  if (serialized.includes(forbidden)) problems.push(`dashboard contains forbidden secret prefix ${forbidden}`);
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

console.log(`Validated ${dashboard.panels.length} panels and ${ids.size} unique panel IDs.`);
