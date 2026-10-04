"""Unit tests for Dockerfile AST and static parser."""

from __future__ import annotations

from vuln_ai.container.dockerfile import (
    extract_package_installs,
    parse_base_image_ref,
    parse_dockerfile_content,
)


def test_parse_base_image_ref():
    """Verify base image tag and digest parsing."""
    ref1 = parse_base_image_ref("python:3.12-slim")
    assert ref1.name == "python"
    assert ref1.tag == "3.12-slim"
    assert ref1.digest is None

    # Host with port
    ref2 = parse_base_image_ref("registry.internal:5000/my-org/app:v2.1")
    assert ref2.name == "registry.internal:5000/my-org/app"
    assert ref2.tag == "v2.1"

    # Pinned with sha256
    ref3 = parse_base_image_ref("node:22-alpine@sha256:abcdef123456")
    assert ref3.name == "node"
    assert ref3.tag == "22-alpine"
    assert ref3.digest == "sha256:abcdef123456"

    # Without tag
    ref4 = parse_base_image_ref("scratch")
    assert ref4.name == "scratch"
    assert ref4.tag == "latest"


def test_extract_package_installs():
    """Verify static package extraction across package managers."""
    # apt-get
    apt_inst = extract_package_installs(
        "apt-get update && apt-get install -y curl libssl-dev git", 5, "build"
    )
    assert len(apt_inst) == 1
    assert apt_inst[0]["manager"] == "apt"
    assert "curl" in apt_inst[0]["packages"]
    assert "libssl-dev" in apt_inst[0]["packages"]
    assert "git" in apt_inst[0]["packages"]
    assert "-y" not in apt_inst[0]["packages"]

    # apk
    apk_inst = extract_package_installs(
        "apk add --no-cache openssl bash ca-certificates", 8, "runtime"
    )
    assert len(apk_inst) == 1
    assert apk_inst[0]["manager"] == "apk"
    assert "openssl" in apk_inst[0]["packages"]
    assert "bash" in apk_inst[0]["packages"]

    # yum
    yum_inst = extract_package_installs("yum install -y httpd python3", 10, "runtime")
    assert len(yum_inst) == 1
    assert yum_inst[0]["manager"] == "yum"
    assert "httpd" in yum_inst[0]["packages"]

    # pip
    pip_inst = extract_package_installs(
        "pip install -r requirements.txt requests flask", 12, "runtime"
    )
    assert len(pip_inst) == 1
    assert pip_inst[0]["manager"] == "pip"
    assert "requests" in pip_inst[0]["packages"]
    assert "requirements.txt" in pip_inst[0]["requirement_files"]

    # npm
    npm_inst = extract_package_installs("npm install express lodash", 14, "builder")
    assert len(npm_inst) == 1
    assert npm_inst[0]["manager"] == "npm"
    assert "express" in npm_inst[0]["packages"]


def test_multi_stage_dockerfile_ast():
    """Verify multi-stage build AST parsing and runtime stage identification."""
    dockerfile_text = """# Multi-stage build example
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Runtime final stage
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
RUN apk add --no-cache curl
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
"""
    doc = parse_dockerfile_content(dockerfile_text, source_file="Dockerfile.test")

    assert len(doc.stages) == 2
    # Stage 0: builder
    assert doc.stages[0].name == "builder"
    assert doc.stages[0].base_image.name == "node"
    assert doc.stages[0].base_image.tag == "22-alpine"
    assert doc.stages[0].is_runtime is False

    # Stage 1: runtime (last stage)
    assert doc.stages[1].name == "1"
    assert doc.stages[1].base_image.name == "nginx"
    assert doc.stages[1].base_image.tag == "alpine"
    assert doc.stages[1].is_runtime is True

    # Check detected manifests
    assert "package.json" in doc.dependency_manifests
    assert "package-lock.json" in doc.dependency_manifests

    # Check copies
    assert any(c.get("from_stage") == "builder" for c in doc.copied_files)

    # Line numbers preserved
    assert doc.instructions[0].instruction == "FROM"
    assert doc.instructions[0].line_number == 2


def test_extract_apt_pinned_versions():
    """H8: apt-get install package=version must enter package_installations."""
    pinned = extract_package_installs(
        "apt-get update && apt-get install -y curl=7.88.1-1 openssl=3.0.2-0ubuntu1",
        7,
        "runtime",
    )
    assert len(pinned) == 1
    assert pinned[0]["manager"] == "apt"
    assert "curl" in pinned[0]["packages"]
    assert "openssl" in pinned[0]["packages"]
    assert pinned[0]["pinned"] == [
        {"name": "curl", "version": "7.88.1-1"},
        {"name": "openssl", "version": "3.0.2-0ubuntu1"},
    ]


def test_extract_apt_chained_and_multiple():
    installs = extract_package_installs(
        "apt-get update && apt-get install -y --no-install-recommends foo=1.0 bar baz=2.0",
        3,
        "build",
    )
    assert installs[0]["packages"] == ["foo", "bar", "baz"]
    assert {"name": "foo", "version": "1.0"} in installs[0]["pinned"]
