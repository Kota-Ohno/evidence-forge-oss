import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function npmPurl(name, version) {
  const encodedName = name.startsWith("@")
    ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/").slice(1).join("/"))}`
    : encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

function command(arguments_) {
  const result = spawnSync("pnpm", arguments_, { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 30_000 });
  if (result.error || result.status !== 0) throw new Error("Production dependency inventory command failed");
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("Production dependency inventory returned invalid JSON");
  }
}

function licenseMap(inventory) {
  const licenses = new Map();
  for (const [licenseId, records] of Object.entries(inventory)) {
    if (!Array.isArray(records)) throw new Error("Production license inventory is invalid");
    for (const record of records) {
      if (typeof record?.name !== "string" || !Array.isArray(record.versions)) {
        throw new Error("Production license inventory is invalid");
      }
      for (const version of record.versions) {
        const key = `${record.name}@${version}`;
        if (licenses.has(key) && licenses.get(key) !== licenseId) {
          throw new Error("Production license inventory has conflicting evidence");
        }
        licenses.set(key, licenseId);
      }
    }
  }
  return licenses;
}

export function buildProductionSbom({ packageMetadata, dependencyTree, licenseInventory, lockfileBytes }) {
  const root = dependencyTree?.[0];
  if (typeof packageMetadata?.name !== "string" || typeof packageMetadata.version !== "string" ||
      packageMetadata.license !== "MIT" || root?.name !== packageMetadata.name ||
      root.version !== packageMetadata.version || typeof root.dependencies !== "object" || root.dependencies === null) {
    throw new Error("Production dependency tree does not match package metadata");
  }
  const licenses = licenseMap(licenseInventory);
  const components = new Map();
  const relationships = new Map();
  function visit(name, node) {
    if (typeof node?.version !== "string" || node.version.length === 0) {
      throw new Error("Production dependency tree contains an invalid component");
    }
    const key = `${name}@${node.version}`;
    const license = licenses.get(key);
    if (typeof license !== "string" || license.length === 0) {
      throw new Error("Every production component requires a license");
    }
    const ref = npmPurl(name, node.version);
    components.set(ref, {
      type: "library",
      "bom-ref": ref,
      name,
      version: node.version,
      scope: "required",
      licenses: [{ license: { id: license } }],
      purl: ref,
    });
    const children = Object.entries(node.dependencies ?? {}).map(([childName, child]) => visit(childName, child));
    relationships.set(ref, [...new Set([...(relationships.get(ref) ?? []), ...children])].sort());
    return ref;
  }
  const declaredNames = Object.keys(packageMetadata.dependencies ?? {}).sort();
  const installedNames = Object.keys(root.dependencies).sort();
  if (JSON.stringify(declaredNames) !== JSON.stringify(installedNames)) {
    throw new Error("Installed production dependencies do not match package metadata");
  }
  const rootRef = npmPurl(packageMetadata.name, packageMetadata.version);
  const rootChildren = Object.entries(root.dependencies).map(([name, node]) => visit(name, node)).sort();
  relationships.set(rootRef, rootChildren);
  const sortedComponents = [...components.values()].sort((left, right) => left.purl.localeCompare(right.purl));
  const dependencies = [...relationships.entries()]
    .map(([ref, dependsOn]) => ({ ref, dependsOn }))
    .sort((left, right) => left.ref.localeCompare(right.ref));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      component: {
        type: "application",
        "bom-ref": rootRef,
        name: packageMetadata.name,
        version: packageMetadata.version,
        licenses: [{ license: { id: packageMetadata.license } }],
        purl: rootRef,
      },
      properties: [
        { name: "evidence-forge:pnpm-lock-sha256", value: sha256(lockfileBytes) },
        { name: "evidence-forge:reproducible", value: "true" },
      ],
    },
    components: sortedComponents,
    dependencies,
  };
}

export function generateProductionSbom() {
  return buildProductionSbom({
    packageMetadata: JSON.parse(readFileSync("package.json", "utf8")),
    dependencyTree: command(["list", "--prod", "--json", "--depth", "Infinity"]),
    licenseInventory: command(["licenses", "list", "--prod", "--json"]),
    lockfileBytes: readFileSync("pnpm-lock.yaml"),
  });
}

function main() {
  try {
    process.stdout.write(`${JSON.stringify(generateProductionSbom(), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      version: 1,
      kind: "EvidenceForgeProductionSbomError",
      outcome: "error",
      code: "PRODUCTION_SBOM_FAILED",
      message: error instanceof Error ? error.message : "Production SBOM generation failed",
    })}\n`);
    process.exitCode = 1;
  }
}

const isMain = process.argv[1] !== undefined && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) main();
