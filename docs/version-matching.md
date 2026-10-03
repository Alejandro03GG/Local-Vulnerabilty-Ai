# Version-Aware Semantic Matching

The **Version-Aware Matcher** (`vuln_ai.matching.matcher` & `vuln_ai.matching.version`) determines whether an installed software dependency version falls within the vulnerability intervals defined by authoritative intelligence advisories.

---

## 1. Ecosystem Versioning Strategies

Software package ecosystems follow distinct versioning grammars. The matcher implements specialized comparison strategies rather than relying on generic string comparisons:

| Ecosystem | Canonical Strategy | Implementation / Library | Grammar Specification |
| :--- | :--- | :--- | :--- |
| **PyPI** (Python) | `PEP440Strategy` | `packaging.version.Version` | PEP 440 (e.g., `2.1.0rc1`, `2.0.post1`, `1.5.dev0`) |
| **npm** (JavaScript) | `SemVerStrategy` | `semver.Version` | Semantic Versioning 2.0.0 |
| **Cargo** (Rust) | `SemVerStrategy` | `semver.Version` | Semantic Versioning 2.0.0 |
| **Go** (Golang) | `SemVerStrategy` | `semver.Version` | Pseudo-versions & SemVer 2.0.0 |
| **NuGet** (.NET) | `SemVerStrategy` | `semver.Version` | 4-part & SemVer 2.0.0 |
| **Maven** (Java) | `MavenStrategy` | `MavenVersionComparator` | Maven Artifact Version Ordering Specification |
| **Unsupported** | `UnknownStrategy` | Fail-safe fallback | Returns `Applicability.UNKNOWN` |

---

## 2. Event Range Types & Mathematical Intervals

Advisories declare applicability intervals via event markers. The matcher translates these into rigorous mathematical sets:

### 2.1 Introduced + Fixed: $[introduced, fixed)$
- **Definition**: The vulnerability began at `introduced` (inclusive) and was remediated in `fixed` (exclusive).
- **Evaluation**: $installed \ge introduced \land installed < fixed$.
- **Example**: Introduced `2.0.0`, Fixed `2.4.0`. Installed `2.3.1` $\to$ `LIKELY_AFFECTED`. Installed `2.4.0` $\to$ `LIKELY_NOT_AFFECTED`.

### 2.2 Introduced + Limit: $[introduced, limit)$
- **Definition**: The upper boundary is marked by an OSV `limit` event indicating an unconfirmed upper ceiling.
- **Evaluation**: The limit version itself is **excluded** from affected status ($installed < limit$).
- **Example**: Introduced `1.0.0`, Limit `3.0.0`. Installed `2.9.0` $\to$ `LIKELY_AFFECTED`. Installed `3.0.0` $\to$ `LIKELY_NOT_AFFECTED`.

### 2.3 Introduced + Last Affected: $[introduced, last\_affected]$
- **Definition**: The vulnerability extends through `last_affected` inclusively.
- **Evaluation**: $installed \ge introduced \land installed \le last\_affected$.
- **Example**: Introduced `1.0.0`, Last Affected `1.5.0`. Installed `1.5.0` $\to$ `LIKELY_AFFECTED`. Installed `1.5.1` $\to$ `LIKELY_NOT_AFFECTED`.

### 2.4 Open / Introduced-Only Range: $[introduced, \infty)$
- **Definition**: The vulnerability was introduced at a known version, but no fixed version has been published.
- **Evaluation**: $installed \ge introduced$. Evaluates to `LIKELY_AFFECTED`.

---

## 3. Edge Cases & Safety Fallbacks

### 3.1 Unsupported Ecosystems
If an advisory or component belongs to an ecosystem without a supported comparison engine, the matcher refuses to guess:
```text
Installed version: 1.2.3
Ecosystem: Arch Linux PKGBUILD
Verdict: Applicability.UNKNOWN
Evidence: "Unsupported ecosystem 'arch'; version parsing deferred to human triage"
```

### 3.2 Catalog-Only Matches (e.g., CISA KEV without Range)
When a component name matches an advisory catalog entry that lacks structured version range events:
```text
Component: log4j 1.2.17
Advisory: CVE-2021-44228 (CISA KEV)
Range events: None declared
Verdict: Applicability.DETECTED
Evidence: "Matched in catalog without explicit version bounds"
```

### 3.3 Invalid Version Strings
If a declared version string cannot be parsed under the ecosystem's specification grammar (e.g., unexpanded git commit hashes or arbitrary strings), the matcher records:
- Verdict: `Applicability.UNKNOWN`.
- Evidence: Explicit parsing failure note.
- Never raises uncaught exceptions.

---

## 4. Frontend Isolation

The frontend web console remains strictly isolated from version parsing logic:
- The UI **never** compares version strings.
- The UI **never** resolves ranges.
- The frontend consumes the structured `MatchEvidence` and `applicability` verdict supplied directly by the API.
