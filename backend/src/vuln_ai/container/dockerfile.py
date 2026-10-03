"""Static AST parser and analyzer for Dockerfiles.

Provides structured analysis of:
- Build stages and multi-stage workflows
- Base images (name, tag, digest, alias)
- Package installations (apt-get, apk, yum, dnf, pip, npm)
- Filesystem copies (COPY/ADD with --from stage provenance)
- Dependency manifest identification
- Strict NO-EXECUTION guarantee (pure AST tokenization)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from vuln_ai.container.models import (
    BaseImageReference,
    DockerfileDocument,
    DockerfileInstruction,
    DockerfileStage,
)

logger = logging.getLogger(__name__)

# Known dependency manifest filenames
_MANIFEST_PATTERNS = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
}


def parse_base_image_ref(
    image_str: str, stage_alias: str | None = None, location: str = ""
) -> BaseImageReference:
    """Parse an image reference string like 'python:3.12-slim@sha256:... AS builder'."""
    image_part = image_str.split()[0].strip()

    digest = None
    if "@" in image_part:
        image_part, digest = image_part.split("@", 1)

    tag = "latest"
    name = image_part
    if ":" in image_part:
        # Care with repository host:port/name
        last_colon = image_part.rfind(":")
        slash_pos = image_part.rfind("/")
        if last_colon > slash_pos:
            name = image_part[:last_colon]
            tag = image_part[last_colon + 1 :]

    return BaseImageReference(
        name=name,
        tag=tag,
        digest=digest,
        stage=stage_alias,
        source_location=location,
    )


def extract_package_installs(cmd: str, line_no: int, stage_name: str) -> list[dict[str, Any]]:
    """Statically parse package management commands within a RUN instruction."""
    installs: list[dict[str, Any]] = []

    # APT / APT-GET
    apt_matches = re.finditer(
        r"(?:apt-get|apt)\s+(?:install|dist-upgrade)\s+([^;&|]+)",
        cmd,
        re.IGNORECASE,
    )
    for m in apt_matches:
        tokens = m.group(1).split()
        packages = [
            t
            for t in tokens
            if not t.startswith("-")
            and "=" not in t
            and t not in ("--no-install-recommends", "-y")
        ]
        if packages:
            installs.append(
                {
                    "manager": "apt",
                    "packages": packages,
                    "stage": stage_name,
                    "line": line_no,
                    "raw_command": cmd.strip(),
                }
            )

    # APK
    apk_matches = re.finditer(r"apk\s+add\s+([^;&|]+)", cmd, re.IGNORECASE)
    for m in apk_matches:
        tokens = m.group(1).split()
        packages = [t for t in tokens if not t.startswith("-") and t not in ("--no-cache", "-u")]
        if packages:
            installs.append(
                {
                    "manager": "apk",
                    "packages": packages,
                    "stage": stage_name,
                    "line": line_no,
                    "raw_command": cmd.strip(),
                }
            )

    # YUM / DNF
    yum_matches = re.finditer(r"(?:yum|dnf)\s+install\s+([^;&|]+)", cmd, re.IGNORECASE)
    for m in yum_matches:
        tokens = m.group(1).split()
        packages = [t for t in tokens if not t.startswith("-") and t != "-y"]
        if packages:
            installs.append(
                {
                    "manager": "yum",
                    "packages": packages,
                    "stage": stage_name,
                    "line": line_no,
                    "raw_command": cmd.strip(),
                }
            )

    # PIP
    pip_matches = re.finditer(r"pip\s+install\s+([^;&|]+)", cmd, re.IGNORECASE)
    for m in pip_matches:
        tokens = m.group(1).split()
        req_files = [
            tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t in ("-r", "--requirement")
        ]
        pkgs = [t for t in tokens if not t.startswith("-") and t not in req_files]
        installs.append(
            {
                "manager": "pip",
                "packages": pkgs,
                "requirement_files": req_files,
                "stage": stage_name,
                "line": line_no,
                "raw_command": cmd.strip(),
            }
        )

    # NPM
    npm_matches = re.finditer(r"npm\s+(?:install|add|ci)\s+([^;&|]+)", cmd, re.IGNORECASE)
    for m in npm_matches:
        tokens = m.group(1).split()
        pkgs = [t for t in tokens if not t.startswith("-")]
        installs.append(
            {
                "manager": "npm",
                "packages": pkgs,
                "stage": stage_name,
                "line": line_no,
                "raw_command": cmd.strip(),
            }
        )

    return installs


def parse_dockerfile_content(content: str, source_file: str = "Dockerfile") -> DockerfileDocument:
    """Parse Dockerfile content into a structured DockerfileDocument AST."""
    raw_lines = content.splitlines()

    # Consolidate continuation lines (\)
    merged_lines: list[tuple[int, str]] = []
    current_line = ""
    start_line_no = 1

    for line_idx, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not current_line:
            start_line_no = line_idx

        if stripped.endswith("\\"):
            current_line += stripped[:-1].strip() + " "
        else:
            current_line += stripped
            merged_lines.append((start_line_no, current_line.strip()))
            current_line = ""

    if current_line:
        merged_lines.append((start_line_no, current_line.strip()))

    instructions: list[DockerfileInstruction] = []
    stages: list[DockerfileStage] = []
    base_images: list[BaseImageReference] = []
    package_installs: list[dict[str, Any]] = []
    copied_files: list[dict[str, Any]] = []
    detected_manifests: set[str] = set()

    current_stage_idx = -1
    current_stage_name = "default"

    for line_no, full_line in merged_lines:
        parts = full_line.split(None, 1)
        if not parts:
            continue

        inst_verb = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""

        if inst_verb == "FROM":
            current_stage_idx += 1
            # Check for AS <alias>
            from_parts = re.split(r"\s+AS\s+", args, flags=re.IGNORECASE)
            image_spec = from_parts[0].strip()
            alias = from_parts[1].strip() if len(from_parts) > 1 else str(current_stage_idx)
            current_stage_name = alias

            base_ref = parse_base_image_ref(
                image_spec,
                stage_alias=alias,
                location=f"{source_file}:{line_no}",
            )
            base_images.append(base_ref)

            stage = DockerfileStage(
                index=current_stage_idx,
                name=current_stage_name,
                base_image=base_ref,
                instructions=[],
                is_runtime=False,  # Updated at the end
            )
            stages.append(stage)

        instruction = DockerfileInstruction(
            line_number=line_no,
            instruction=inst_verb,
            arguments=args,
            stage=current_stage_name,
            raw=full_line,
        )
        instructions.append(instruction)

        if stages:
            stages[-1].instructions.append(instruction)

        # Inspect RUN for package manager invocations
        if inst_verb == "RUN":
            installs = extract_package_installs(args, line_no, current_stage_name)
            package_installs.extend(installs)

        # Inspect COPY and ADD
        if inst_verb in ("COPY", "ADD"):
            from_stage = None
            copy_args = args
            from_match = re.search(r"--from=([^\s]+)", args, re.IGNORECASE)
            if from_match:
                from_stage = from_match.group(1)
                copy_args = re.sub(r"--from=[^\s]+", "", args).strip()

            tokens = copy_args.split()
            if len(tokens) >= 2:
                sources = tokens[:-1]
                dest = tokens[-1]
                for src in sources:
                    copied_files.append(
                        {
                            "instruction": inst_verb,
                            "source": src,
                            "destination": dest,
                            "from_stage": from_stage,
                            "current_stage": current_stage_name,
                            "line": line_no,
                        }
                    )
                    base_name = Path(src).name
                    if base_name in _MANIFEST_PATTERNS:
                        detected_manifests.add(base_name)

    # In Docker multi-stage builds, the LAST stage is the runtime stage
    if stages:
        for st in stages:
            st.is_runtime = False
        stages[-1].is_runtime = True

    return DockerfileDocument(
        source_file=source_file,
        stages=stages,
        instructions=instructions,
        base_images=base_images,
        package_installations=package_installs,
        copied_files=copied_files,
        dependency_manifests=sorted(detected_manifests),
    )


def parse_dockerfile_file(file_path: str | Path) -> DockerfileDocument:
    """Parse a Dockerfile from a filesystem path."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Dockerfile not found: {path}")
    content = path.read_text(encoding="utf-8", errors="replace")
    return parse_dockerfile_content(content, source_file=str(path))
