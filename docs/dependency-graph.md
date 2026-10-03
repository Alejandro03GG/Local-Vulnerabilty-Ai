# Dependency Graph & Lockfile Intelligence

Local Vulnerability AI provides deterministic, local-first dependency graph extraction and lockfile resolution across Python, Node.js, and Rust ecosystems.

---

## 1. Overview & Core Principle

The system adheres to the architectural rule:

```text
LOCKFILE > MANIFEST
```

- When a valid lockfile is present, it is the **primary source of truth** for resolved component versions.
- Manifests (e.g. `requirements.txt`, `pyproject.toml`, `package.json`, `Cargo.toml`) define declared dependency boundaries and identify **direct dependencies**.
- When lockfiles specify transitive dependencies and their parent relationships, the system reconstructs the full dependency chain without executing any external package managers (`pip`, `poetry`, `npm`, `pnpm`, `cargo`).

```text
Manifest / Lockfile
        ↓
Dependency Resolution
        ↓
Dependency Graph (Nodes & Edges)
        ↓
Resolved Components (Direct / Transitive)
        ↓
Version-aware Matcher (Evidence & Range Checks)
        ↓
Conflict Resolution
        ↓
AI Analysis / SystemOne (Supplementary)
        ↓
Deterministic Risk Engine
```

---

## 2. Supported Ecosystems and Lockfiles

| Ecosystem | Manifest | Lockfile | Formats Supported |
| :--- | :--- | :--- | :--- |
| **Python** | `requirements.txt`, `pyproject.toml` | `poetry.lock` | Poetry TOML (v1/v2 format, groups, files metadata, hashes) |
| **Node.js (npm)** | `package.json` | `package-lock.json` | npm lockfileVersion 1, 2, and 3 with nested `node_modules` |
| **Node.js (pnpm)**| `package.json` | `pnpm-lock.yaml` | pnpm YAML format (v5, v6, v9 importers and package entries) |
| **Rust (Cargo)**  | `Cargo.toml` | `Cargo.lock` | Cargo TOML format (v1, v2, v3, workspace crates, checksums) |

---

## 3. Direct vs Transitive Classification

Each resolved component is deterministically classified:

- **`DIRECT`**: A dependency explicitly requested in the project's root manifest or root lockfile declaration.
- **`TRANSITIVE`**: A dependency introduced indirectly as a prerequisite of another dependency.
- **`UNKNOWN`**: Fallback when no manifest or hierarchy is available to ascertain directness.

### Dependency Path Provenance

Every transitive component traces its resolution path back to a direct root dependency.
For example, if `my-project` depends directly on `fastapi`:

```text
fastapi (DIRECT)
  └── starlette (TRANSITIVE)
        └── anyio (TRANSITIVE)
```

The component `anyio` records:
- `is_direct = False`
- `dependency_type = "transitive"`
- `parent_name = "starlette"`
- `dependency_path = ["fastapi", "starlette", "anyio"]`

---

## 4. Multi-Version Resolution

In ecosystems like npm and Cargo, different subtrees in a project can resolve distinct versions of the same package simultaneously (e.g., `lodash@3.10.1` and `lodash@4.17.21`, or `serde 1.0.197` and `serde 0.9.0`).

Local Vulnerability AI distinguishes components by identity:

```text
node_id = f"{ecosystem}:{normalized_name}:{version}"
```

Each version is evaluated independently against the vulnerability catalog. A vulnerability affecting `lodash@3.x` will NOT erroneously flag `lodash@4.x`.

---

## 5. Security & Isolation Boundaries

1. **Purely Static Analysis**: The scanner **never** executes package managers (`npm install`, `cargo audit`, `pip install`, `poetry run`, etc.).
2. **Safe Deserialization**:
   - YAML files (`pnpm-lock.yaml`) are strictly parsed using `yaml.safe_load`. Custom YAML constructors or object deserialization are rejected.
   - TOML files are parsed using Python's standard `tomllib`.
   - JSON files are parsed using Python's standard `json`.
3. **Cycle Protection**: Lockfile structures with circular dependencies (or crafted malicious cyclic graphs) are guarded using depth-limited breadth-first search and Tarjan-style cycle detection. Circular dependencies do not crash the engine or exhaust recursion limits.
4. **Denial of Service Limits**:
   - Maximum lockfile size is enforced (default 30 MB).
   - Database bulk upserts are chunked to prevent host parameter saturation in SQLite.

---

## 6. Error Handling & Fallbacks

- **Corrupted Lockfile**: Structured log error and graceful fallback without crashing. Does not invent versions or mark components as vulnerable.
- **Manifest Only**: If a lockfile is absent, manifest scanners (e.g., `requirements.txt`, `package.json`, `Cargo.toml`) detect declared constraints.
- **Lockfile with missing Manifest**: Direct dependencies are inferred from packages with zero incoming dependencies.

---

## 7. Known Limitations

- **Dynamic Package Scripts**: Packages resolved dynamically at runtime (e.g., dynamic imports `import(variable)` or custom build scripts) are not tracked.
- **Yarn Lockfile (`yarn.lock`)**: Scheduled for Etapa 15.
- **Complex Monorepo Workspaces**: Top-level workspaces are fully supported; deeply nested multi-package monorepos with custom symlinks may require scanning per workspace folder.
