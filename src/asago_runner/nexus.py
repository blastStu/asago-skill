"""IBM AI Atlas Nexus dependency resolution and runner-managed data cache.

The Policy Mapper loads Nexus risk data from a local clone passed via
``--nexus-base-dir`` and requires it to match the *installed* ``ai-atlas-nexus``
library revision. This module:

1. resolves the effective installed dependency (importlib.metadata +
   ``direct_url.json`` VCS commit, cross-checked against the import location);
2. fetches the required tracked data files at exactly that commit into a
   runner-managed cache (partial clone, sparse checkout of the data tree the
   native loader and the mapper's mitigation enrichment read), so users never
   need to find or maintain a separate clone;
3. verifies the cache against a recorded file-hash manifest and against the
   installed distribution's own bundled data (content provenance check);
4. exercises the native ``AIAtlasNexus(base_dir=...).get_all_risks()`` loading
   path with the mapper CLI's taxonomy exclusions and description overrides.

A sparse data subset is used because the native loader's complete file
requirements are established here: ``load_yamls_to_container`` globs
``**/*.yaml`` under the base dir (merged with the installed package's bundled
data by entity id), and the mapper's mitigation enrichment reads specific
files under ``src/ai_atlas_nexus/data/knowledge_graph``. The subset is
validated by exercising the loader and comparing its unfiltered output with
the installed-package-only load.

Never a floating ``main`` revision: the fetch is always at the resolved
commit. Failure to fetch or verify is an actionable preflight blocker.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import atomic_write_json, utc_now_iso
from .hashing import sha256_file

NEXUS_REPO_URL = "https://github.com/IBM/ai-atlas-nexus.git"
# Complete file requirements of the native loader and the mapper's
# mitigation enrichment (see module docstring). This is the sparse subset.
NEXUS_DATA_SUBDIR = "src/ai_atlas_nexus/data"
MANIFEST_NAME = "asago-runner-cache.json"


class NexusError(RuntimeError):
    """Nexus dependency/data pairing could not be resolved or verified."""


@dataclass
class NexusResolution:
    """The effective installed ai-atlas-nexus dependency identity."""

    version: str
    commit: str | None
    direct_url: str | None
    import_location: str
    dist_location: str
    import_matches_dist: bool
    verifiable: bool
    note: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "commit": self.commit,
            "direct_url": self.direct_url,
            "import_location": self.import_location,
            "dist_location": self.dist_location,
            "import_matches_dist": self.import_matches_dist,
            "verifiable": self.verifiable,
            "note": self.note,
        }


@dataclass
class NexusCacheResult:
    cache_dir: str
    commit: str
    files: dict[str, str]
    fetched_now: bool
    verified: bool
    findings: list[str] = field(default_factory=list)
    loader: dict[str, Any] | None = None
    resolution: NexusResolution | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "cache_dir": self.cache_dir,
            "commit": self.commit,
            "file_count": len(self.files),
            "fetched_now": self.fetched_now,
            "verified": self.verified,
            "findings": self.findings,
            "loader": self.loader,
            "resolution": self.resolution.summary() if self.resolution else None,
        }


def resolve_nexus_dependency() -> NexusResolution:
    """Resolve the effective installed ai-atlas-nexus dependency identity.

    A wheel without VCS metadata has no verifiable commit and is reported as
    unverifiable rather than passed on a version label.
    """
    import importlib.metadata as im

    try:
        dist = im.distribution("ai-atlas-nexus")
    except im.PackageNotFoundError as exc:
        raise NexusError(
            "ai-atlas-nexus is not installed in the runner environment. "
            "Run `uv sync --locked` from the skill root."
        ) from exc

    direct_url_raw = dist.read_text("direct_url.json")
    commit: str | None = None
    url: str | None = None
    if direct_url_raw:
        info = json.loads(direct_url_raw)
        url = info.get("url")
        vcs = info.get("vcs_info") or {}
        commit = vcs.get("commit_id")
    import asago_policy_mapper  # noqa: F401  (ensure env is importable)

    import ai_atlas_nexus

    import_location = str(Path(ai_atlas_nexus.__file__).resolve().parent)
    dist_location = str(Path(dist.locate_file("ai_atlas_nexus")).resolve())
    import_matches_dist = import_location == dist_location

    note = None
    verifiable = bool(commit)
    if not commit:
        note = (
            "installed distribution has no VCS commit metadata (direct_url.json); "
            "data/dependency pairing cannot be verified from provenance"
        )
    elif not import_matches_dist:
        note = "import location differs from the distribution location (override in effect)"
        verifiable = False

    return NexusResolution(
        version=dist.version,
        commit=commit,
        direct_url=url,
        import_location=import_location,
        dist_location=dist_location,
        import_matches_dist=import_matches_dist,
        verifiable=verifiable,
        note=note,
    )


def _git(args: list[str], cwd: Path | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise NexusError(
            f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:400]}"
        )
    return proc.stdout.strip()


def nexus_cache_dir(base_cache_dir: str | Path, commit: str) -> Path:
    return Path(base_cache_dir).resolve() / "nexus" / commit


def _fetch_sparse(repo_url: str, commit: str, target: Path, subdir: str) -> None:
    """Fetch exactly ``subdir`` at ``commit`` into ``target`` (partial clone)."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise NexusError(f"cache path already exists: {target}")
    target.mkdir()
    try:
        _git(["init", "--quiet"], cwd=target)
        _git(["remote", "add", "origin", repo_url], cwd=target)
        _git(
            [
                "config",
                "remote.origin.promisor",
                "true",
            ],
            cwd=target,
        )
        _git(["config", "remote.origin.partialclonefilter", "blob:none"], cwd=target)
        _git(
            [
                "sparse-checkout",
                "init",
                "--cone",
            ],
            cwd=target,
        )
        _git(["sparse-checkout", "set", subdir], cwd=target)
        _git(
            ["fetch", "--quiet", "--depth", "1", "origin", commit],
            cwd=target,
            check=False,
        )
        head = _git(["rev-parse", "FETCH_HEAD"], cwd=target, check=False)
        if not head:
            raise NexusError(
                f"could not fetch {repo_url} at commit {commit}. The pinned "
                "commit may be unavailable (network, permissions, or the "
                "revision was force-pushed away)."
            )
        if head != commit:
            raise NexusError(
                f"fetched commit {head} does not equal the required {commit}"
            )
        _git(["checkout", "--quiet", "FETCH_HEAD"], cwd=target)
    except Exception:
        # Leave no half-built cache behind.
        import shutil

        shutil.rmtree(target, ignore_errors=True)
        raise


def _manifest_path(cache_dir: Path) -> Path:
    return cache_dir / MANIFEST_NAME


def _write_manifest(cache_dir: Path, commit: str, fetched_now: bool) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted((cache_dir / NEXUS_DATA_SUBDIR).rglob("*")):
        if path.is_file() and path.suffix in (".yaml", ".yml"):
            files[str(path.relative_to(cache_dir))] = sha256_file(path)
    manifest = {
        "schema_version": 1,
        "repo_url": NEXUS_REPO_URL,
        "commit": commit,
        "subdir": NEXUS_DATA_SUBDIR,
        "fetched_at": utc_now_iso(),
        "fetched_now": fetched_now,
        "files": files,
    }
    atomic_write_json(_manifest_path(cache_dir), manifest)
    return files


def _verify_cache(cache_dir: Path, resolution: NexusResolution) -> list[str]:
    """Verify cache integrity; returns findings (empty = verified)."""
    findings: list[str] = []
    manifest_path = _manifest_path(cache_dir)
    if not manifest_path.is_file():
        return [f"cache manifest missing at {manifest_path}"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("commit") != resolution.commit:
        findings.append(
            f"cache commit {manifest.get('commit')} != installed dependency commit "
            f"{resolution.commit}: the environment and data cache disagree"
        )
    # 1. Every recorded file must exist with the recorded hash (detects local
    #    modification; a Git tree ID alone would not).
    for rel, expected in manifest.get("files", {}).items():
        path = cache_dir / rel
        if not path.is_file():
            findings.append(f"cache file missing: {rel}")
        elif sha256_file(path) != expected:
            findings.append(f"cache file modified relative to manifest: {rel}")
    # 2. No unmanifested YAML files (detects injected extra data).
    actual = {
        str(p.relative_to(cache_dir))
        for p in (cache_dir / NEXUS_DATA_SUBDIR).rglob("*")
        if p.is_file() and p.suffix in (".yaml", ".yml")
    }
    extra = actual - set(manifest.get("files", {}))
    if extra:
        findings.append(f"unmanifested data files present: {sorted(extra)[:5]}")
    # 3. Git HEAD still at the required commit.
    head = _git(["rev-parse", "HEAD"], cwd=cache_dir, check=False)
    if resolution.commit and head != resolution.commit:
        findings.append(f"cache git HEAD {head} != required commit {resolution.commit}")
    # 4. Installed distribution's bundled data must match the cache content:
    #    same file set, same hashes. This validates the installed dist's data
    #    provenance against the fetched revision bytes.
    installed_data = Path(resolution.import_location) / "data"
    cache_data = cache_dir / NEXUS_DATA_SUBDIR
    installed_files = {
        str(p.relative_to(installed_data)): sha256_file(p)
        for p in sorted(installed_data.rglob("*"))
        if p.is_file() and p.suffix in (".yaml", ".yml")
    }
    cache_files = {
        str(p.relative_to(cache_data)): sha256_file(p)
        for p in sorted(cache_data.rglob("*"))
        if p.is_file() and p.suffix in (".yaml", ".yml")
    }
    if set(installed_files) != set(cache_files):
        only_installed = sorted(set(installed_files) - set(cache_files))[:5]
        only_cache = sorted(set(cache_files) - set(installed_files))[:5]
        findings.append(
            "installed package data files differ from the fetched revision data "
            f"(only installed: {only_installed}; only cache: {only_cache})"
        )
    else:
        for rel, expected in installed_files.items():
            if cache_files[rel] != expected:
                findings.append(
                    f"installed package data file {rel} differs from the fetched "
                    "revision bytes (stale or modified installation)"
                )
                break
    return findings


def exercise_native_loader(cache_dir: Path) -> dict[str, Any]:
    """Run the mapper's real Nexus loading path, model-free.

    Applies the same taxonomy exclusions and description overrides as the
    mapper CLI, records counts before and after filtering, inventories extra
    loaded files and compares against an installed-package-only load.
    """
    from ai_atlas_nexus import AIAtlasNexus

    from asago_policy_mapper.cli import EXCLUDED_TAXONOMIES
    from asago_policy_mapper.taxonomy import apply_description_overrides

    with_cache = AIAtlasNexus(base_dir=str(cache_dir))
    all_risks = list(with_cache.get_all_risks())
    filtered = apply_description_overrides(
        r
        for r in all_risks
        if getattr(r, "isDefinedByTaxonomy", "") not in EXCLUDED_TAXONOMIES
    )
    filtered_list = list(filtered)

    # Reference load: installed package data only (no base_dir override).
    package_only = AIAtlasNexus(base_dir=None)
    package_risks = list(package_only.get_all_risks())

    def _tax_counts(risks: list) -> dict[str, int]:
        counts: dict[str, int] = {}
        for risk in risks:
            tax = getattr(risk, "isDefinedByTaxonomy", "") or "unknown"
            counts[tax] = counts.get(tax, 0) + 1
        return dict(sorted(counts.items()))

    return {
        "loaded_with_base_dir": len(all_risks),
        "loaded_package_only": len(package_risks),
        "counts_agree": len(all_risks) == len(package_risks),
        "after_mapper_exclusions": len(filtered_list),
        "excluded_taxonomies": sorted(EXCLUDED_TAXONOMIES),
        "taxonomy_counts_before_filter": _tax_counts(all_risks),
        "description_overrides_applied": True,
        "base_dir": str(cache_dir),
    }


def ensure_nexus_cache(
    base_cache_dir: str | Path,
    *,
    resolution: NexusResolution | None = None,
    fetch: bool = True,
) -> NexusCacheResult:
    """Ensure a verified Nexus data cache for the resolved dependency commit.

    Reuses a verified cached copy; otherwise fetches at the exact commit.
    """
    resolution = resolution or resolve_nexus_dependency()
    if not resolution.verifiable or not resolution.commit:
        raise NexusError(
            "the installed ai-atlas-nexus dependency is not verifiable to a "
            "commit; cannot pair it with data. Install the runner environment "
            "from its lock file (`uv sync --locked`). "
            + (resolution.note or "")
        )

    commit = resolution.commit
    cache_dir = nexus_cache_dir(base_cache_dir, commit)
    fetched_now = False
    if not cache_dir.is_dir():
        if not fetch:
            raise NexusError(
                f"Nexus data for commit {commit[:12]} is not cached at {cache_dir} "
                "and fetching is disabled"
            )
        _fetch_sparse(NEXUS_REPO_URL, commit, cache_dir, NEXUS_DATA_SUBDIR)
        _write_manifest(cache_dir, commit, fetched_now=True)
        fetched_now = True
    elif not _manifest_path(cache_dir).is_file():
        # Cache exists without a runner manifest (e.g. a user-managed clone was
        # placed there). Verify-then-manifest it rather than trusting it.
        _write_manifest(cache_dir, commit, fetched_now=False)

    findings = _verify_cache(cache_dir, resolution)
    result = NexusCacheResult(
        cache_dir=str(cache_dir),
        commit=commit,
        files=json.loads(_manifest_path(cache_dir).read_text(encoding="utf-8"))[
            "files"
        ],
        fetched_now=fetched_now,
        verified=not findings,
        findings=findings,
        resolution=resolution,
    )
    if findings:
        raise NexusError(
            "Nexus data cache verification failed: " + "; ".join(findings)
        )
    return result
