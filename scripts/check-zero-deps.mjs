/**
 * CI guard: the published package must have zero runtime dependencies.
 * Fails if package.json contains a non-empty `dependencies` (or accidental
 * `peerDependencies` made mandatory) map.
 */
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const deps = Object.keys(pkg.dependencies ?? {});
if (deps.length > 0) {
  console.error(`zero-deps check failed: runtime dependencies found: ${deps.join(', ')}`);
  process.exit(1);
}

const mandatoryPeers = Object.entries(pkg.peerDependencies ?? {}).filter(
  ([name]) => pkg.peerDependenciesMeta?.[name]?.optional !== true,
);
if (mandatoryPeers.length > 0) {
  console.error(
    `zero-deps check failed: mandatory peer dependencies found: ${mandatoryPeers
      .map(([name]) => name)
      .join(', ')} (mark them optional in peerDependenciesMeta)`,
  );
  process.exit(1);
}

console.log('zero-deps check passed');
