#!/usr/bin/env python3
r"""Deterministically compare OWASP Noir JSON with noir-ts CSV evidence.

Copy-paste example for existing reports (replace the three ``/path`` values)::

    COMPARISON_DIR="$(mktemp -d /tmp/noir-noirts.XXXXXX)"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
      "/home/rs/rsw/noir-ts.files/_dl/sprint05/tools/compare_noir_noirts.py" \
      "/path/to/noir-report.json" \
      "/path/to/noir-ts-report.csv" \
      --source-root "/path/to/analyzed-source" \
      --output-dir "$COMPARISON_DIR"
    sed -n '1,240p' "$COMPARISON_DIR/comparison.md"

Copy-paste retained Keycloak replay (runs as written and writes only to a
fresh temporary directory)::

    COMPARISON_DIR="$(mktemp -d /tmp/noir-noirts-keycloak.XXXXXX)"
    PYTHONDONTWRITEBYTECODE=1 python3 -B \
      "/home/rs/rsw/noir-ts.files/_dl/sprint05/tools/compare_noir_noirts.py" \
      "/home/rs/rsw/noir-ts.files/_dl/sprint04/reports/noir/01-keycloak-java-api-relative.json" \
      "/home/rs/rsw/noir-ts.files/_dl/sprint04/reports/our-tool/noir-sbt-report.csv" \
      --source-root "/home/rs/rsw/noir-ts.files/_dl/keycloak" \
      --output-dir "$COMPARISON_DIR"
    sed -n '1,240p' "$COMPARISON_DIR/comparison.md"

The two positional arguments are the Noir JSON report and noir-ts semicolon
CSV report. ``--output-dir`` selects the derived report directory (default:
``./comparison-noir-noirts``); ``--source-root`` optionally aligns source-file
evidence to one analyzed checkout. Repeat ``--noir-technology`` to replace the
default Java detector allowlist, or use ``--all-noir-http`` explicitly. The
Noir input must be the single JSON object produced by ``--format json``; JSONL,
YAML, and console text are not accepted. The schema is verified against OWASP
Noir 0.29.0, 0.29.1, and 1.2.1.

The comparator deliberately uses a narrow denominator:

* Noir rows must be non-internal HTTP endpoints in an allowed Java server
  technology. Noir ``internal: true`` rows represent client-side declarations
  in the verified versions and stay outside the inbound-server denominator.
* noir-ts rows must use the direct ``http METHOD`` interface form.
* Exact normalized ``(method, path)`` identity is the primary match tier.
* A conservative secondary tier matches placeholder shapes only when the best
  assignment is unambiguous and every pair has positive source overlap.

Other noir-ts interfaces (WebSocket/message, client, Gateway, static handler,
and unknown forms) and other Noir technologies/protocols are retained in
separate inventories. A row present only in noir-ts is called an additional
static candidate, never an automatically correct endpoint.

Only Python's standard library is used; this file imports no noir-ts workspace
module.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
import math
import os
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
TOOL_VERSION = "0.2.0"
DEFAULT_NOIR_TECHNOLOGIES = (
    "java_jaxrs",
    "java_quarkus",
    "java_spring",
)
NOIR_OUTPUT_NAME = "noir-noncomparable-endpoints.csv"
NOIRTS_EXTRA_OUTPUT_NAME = "noirts-extra-surface-evidence.csv"
MATCHED_OUTPUT_NAME = "matched-http-server-identities.csv"
NOIR_ONLY_OUTPUT_NAME = "noir-only-http-server-identities.csv"
NOIRTS_ONLY_OUTPUT_NAME = "noirts-only-http-server-candidates.csv"
PATH_DISAGREEMENT_OUTPUT_NAME = "source-method-path-disagreements.csv"
AMBIGUOUS_TEMPLATE_OUTPUT_NAME = "ambiguous-template-clusters.csv"
REPORT_OUTPUT_NAME = "comparison.md"
SUMMARY_OUTPUT_NAME = "summary.json"

HTTP_METHOD_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Z-]+"
DIRECT_HTTP_INTERFACE = re.compile(rf"^http (?P<method>{HTTP_METHOD_TOKEN})$")
METHOD_TOKEN = re.compile(rf"^{HTTP_METHOD_TOKEN}$")
REPEATED_SLASH = re.compile(r"/{2,}")

NOIRTS_REQUIRED_COLUMNS = (
    "module_name",
    "interface_type",
    "endpoint",
    "source_file_name",
    "method_name",
    "parameters",
)


class ComparatorError(ValueError):
    """Raised for a malformed or unsupported input report."""


@dataclass(frozen=True, order=True)
class Identity:
    method: str
    path: str


@dataclass
class IdentityEvidence:
    rows: int = 0
    sources: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    handlers: set[str] = field(default_factory=set)


@dataclass
class ParsedNoir:
    endpoint_total: int
    passive_total: int
    comparable: dict[Identity, IdentityEvidence]
    noncomparable: list[dict[str, str]]
    technologies: Counter[str]
    protocols: Counter[str]
    methods: Counter[str]
    url_transforms: Counter[str]
    comparable_source_occurrences: int
    source_styles: set[str]
    technology_metadata_available: bool
    technology_fallback_used: bool


@dataclass
class ParsedNoirts:
    row_total: int
    comparable: dict[Identity, IdentityEvidence]
    extra_rows: list[dict[str, str]]
    interface_types: Counter[str]
    comparable_methods: Counter[str]
    exact_duplicate_rows: int
    source_styles: set[str]


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _json_cell(values: Iterable[str]) -> str:
    return json.dumps(
        sorted(set(values)), ensure_ascii=False, separators=(",", ":")
    )


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_metadata(path: Path) -> dict[str, Any]:
    content = path.read_bytes()
    return {
        "path": str(path.resolve(strict=False)),
        "bytes": len(content),
        "sha256": _sha256_bytes(content),
    }


def _source_style(value: str) -> str:
    if not value:
        return "empty"
    return "absolute" if Path(value).is_absolute() else "relative"


def _normalize_source(value: object, source_root: Path | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    normalized_separators = raw.replace("\\", "/")
    source = Path(normalized_separators)
    if source.is_absolute():
        absolute = source.resolve(strict=False)
        if source_root is not None:
            try:
                return absolute.relative_to(source_root).as_posix()
            except ValueError:
                pass
        return absolute.as_posix()
    normalized = os.path.normpath(normalized_separators).replace("\\", "/")
    return "" if normalized == "." else normalized


def _canonical_server_path(value: object) -> tuple[str | None, str]:
    raw = str(value or "").strip()
    if not raw:
        return None, "empty"

    parsed = urlsplit(raw)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        path = parsed.path or "/"
        transform = "absolute_http_origin_removed"
    else:
        path = raw.split("#", 1)[0].split("?", 1)[0]
        transform = "relative_or_path"

    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    path = REPEATED_SLASH.sub("/", path)
    return path, transform


def _balanced_brace_end(value: str, start: int) -> int | None:
    depth = 0
    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _top_level_colon(content: str) -> int | None:
    depth = 0
    escaped = False
    for index, char in enumerate(content):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "{":
            depth += 1
        elif char == "}" and depth:
            depth -= 1
        elif char == ":" and depth == 0:
            return index
    return None


def _template_shape(path: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(path):
        if path[index] != "{" or (index and path[index - 1] == "$"):
            output.append(path[index])
            index += 1
            continue
        end = _balanced_brace_end(path, index)
        if end is None:
            output.append(path[index])
            index += 1
            continue
        content = path[index + 1 : end]
        colon = _top_level_colon(content)
        if colon is None:
            name = content.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name):
                output.append("{}")
            else:
                output.append(path[index : end + 1])
        else:
            name = content[:colon].strip()
            constraint = content[colon + 1 :]
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name):
                output.append("{:" + constraint + "}")
            else:
                output.append(path[index : end + 1])
        index = end + 1
    return "".join(output)


def _technology(endpoint: Mapping[str, Any]) -> str:
    details = endpoint.get("details")
    if not isinstance(details, Mapping):
        return ""
    value = details.get("technology")
    return str(value or "").strip()


def _internal(endpoint: Mapping[str, Any]) -> bool:
    value = endpoint.get("internal", False)
    if not isinstance(value, bool):
        raise ComparatorError(
            "Noir endpoint internal must be a boolean when present"
        )
    return value


def _noir_sources(
    endpoint: Mapping[str, Any], source_root: Path | None
) -> tuple[list[str], int, set[str]]:
    details = endpoint.get("details")
    code_paths = details.get("code_paths", []) if isinstance(details, Mapping) else []
    if code_paths is None:
        code_paths = []
    if not isinstance(code_paths, list):
        raise ComparatorError("Noir endpoint details.code_paths must be an array")

    sources: list[str] = []
    styles: set[str] = set()
    occurrences = 0
    for code_path in code_paths:
        if not isinstance(code_path, Mapping):
            raise ComparatorError("Noir code_paths entries must be objects")
        raw = str(code_path.get("path") or "").strip()
        if not raw:
            continue
        styles.add(_source_style(raw))
        normalized = _normalize_source(raw, source_root)
        if normalized:
            sources.append(normalized)
            occurrences += 1
    return sources, occurrences, styles


def parse_noir_report(
    path: Path,
    *,
    technologies: frozenset[str],
    all_http_technologies: bool,
    source_root: Path | None,
) -> ParsedNoir:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComparatorError(f"cannot read Noir JSON {path}: {exc}") from exc
    if not isinstance(document, Mapping):
        raise ComparatorError("Noir report root must be an object")
    endpoints = document.get("endpoints")
    passive_results = document.get("passive_results", [])
    if not isinstance(endpoints, list):
        raise ComparatorError("Noir report must contain an endpoints array")
    if not isinstance(passive_results, list):
        raise ComparatorError("Noir passive_results must be an array")

    technology_metadata_available = any(
        bool(_technology(endpoint))
        for endpoint in endpoints
        if isinstance(endpoint, Mapping)
    )
    technology_fallback_used = (
        not all_http_technologies and not technology_metadata_available
    )

    comparable: dict[Identity, IdentityEvidence] = defaultdict(IdentityEvidence)
    noncomparable: list[dict[str, str]] = []
    technology_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    transform_counts: Counter[str] = Counter()
    comparable_source_occurrences = 0
    source_styles: set[str] = set()

    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            raise ComparatorError("Noir endpoints entries must be objects")
        internal = _internal(endpoint)
        protocol = str(endpoint.get("protocol") or "").strip().lower()
        technology = _technology(endpoint)
        method = str(endpoint.get("method") or "").strip().upper()
        url = str(endpoint.get("url") or "").strip()
        technology_counts[technology or "<none>"] += 1
        protocol_counts[protocol or "<none>"] += 1
        method_counts[method or "<none>"] += 1
        sources, occurrences, styles = _noir_sources(endpoint, source_root)
        source_styles.update(styles)
        canonical_path, transform = _canonical_server_path(url)

        reason = ""
        if internal:
            reason = "internal_client"
        elif protocol != "http":
            reason = f"protocol:{protocol or '<none>'}"
        elif (
            not all_http_technologies
            and technology_metadata_available
            and technology not in technologies
        ):
            reason = f"technology:{technology or '<none>'}"
        elif not method or METHOD_TOKEN.fullmatch(method) is None:
            reason = "invalid_method"
        elif canonical_path is None:
            reason = "empty_url"

        if reason:
            noncomparable.append(
                {
                    "reason": reason,
                    "protocol": protocol,
                    "technology": technology,
                    "method": method,
                    "url": url,
                    "canonical_path": canonical_path or "",
                    "sources": _json_cell(sources),
                    "interpretation": (
                        "outside the configured direct Java HTTP server denominator"
                    ),
                }
            )
            continue

        identity = Identity(method, canonical_path)
        evidence = comparable[identity]
        evidence.rows += 1
        evidence.sources.update(sources)
        if technology:
            evidence.technologies.add(technology)
        comparable_source_occurrences += occurrences
        transform_counts[transform] += 1

    return ParsedNoir(
        endpoint_total=len(endpoints),
        passive_total=len(passive_results),
        comparable=dict(comparable),
        noncomparable=noncomparable,
        technologies=technology_counts,
        protocols=protocol_counts,
        methods=method_counts,
        url_transforms=transform_counts,
        comparable_source_occurrences=comparable_source_occurrences,
        source_styles=source_styles,
        technology_metadata_available=technology_metadata_available,
        technology_fallback_used=technology_fallback_used,
    )


def _extra_surface_class(interface_type: str, endpoint: str) -> str:
    if DIRECT_HTTP_INTERFACE.fullmatch(interface_type):
        return "invalid_direct_http_server_row" if not endpoint else "direct_http_unusable"
    if interface_type.startswith("http-client "):
        return "outbound_http_client"
    if interface_type.startswith("http-gateway "):
        return "http_gateway_proxy"
    if interface_type.startswith("http-static-handler "):
        return "http_static_handler"
    if interface_type.startswith("ws "):
        return "websocket_or_messaging"
    return "noncomparable_interface"


def parse_noirts_report(
    path: Path, *, source_root: Path | None
) -> ParsedNoirts:
    try:
        handle = path.open(encoding="utf-8-sig", newline="")
    except (OSError, UnicodeError) as exc:
        raise ComparatorError(f"cannot read noir-ts CSV {path}: {exc}") from exc

    with handle:
        reader = csv.DictReader(handle, delimiter=";")
        if reader.fieldnames is None:
            raise ComparatorError("noir-ts CSV must contain a header")
        if reader.fieldnames != list(NOIRTS_REQUIRED_COLUMNS):
            raise ComparatorError(
                "noir-ts CSV header must exactly equal, in order: "
                + ";".join(NOIRTS_REQUIRED_COLUMNS)
            )
        rows = []
        for line_number, row in enumerate(reader, start=2):
            if None in row:
                raise ComparatorError(
                    f"noir-ts CSV row {line_number} has unexpected extra cells"
                )
            rows.append(
                {
                    name: str(row.get(name) or "")
                    for name in NOIRTS_REQUIRED_COLUMNS
                }
            )

    comparable: dict[Identity, IdentityEvidence] = defaultdict(IdentityEvidence)
    extra_rows: list[dict[str, str]] = []
    interface_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    exact_rows: Counter[tuple[str, ...]] = Counter()
    source_styles: set[str] = set()

    for row in rows:
        interface_type = row["interface_type"].strip()
        endpoint = row["endpoint"].strip()
        source_raw = row["source_file_name"].strip()
        source_styles.add(_source_style(source_raw))
        source = _normalize_source(source_raw, source_root)
        interface_counts[interface_type or "<none>"] += 1
        exact_rows[tuple(row[name] for name in NOIRTS_REQUIRED_COLUMNS)] += 1
        match = DIRECT_HTTP_INTERFACE.fullmatch(interface_type)
        canonical_path, _transform = _canonical_server_path(endpoint)

        if match is not None and canonical_path is not None:
            method = match.group("method")
            identity = Identity(method, canonical_path)
            evidence = comparable[identity]
            evidence.rows += 1
            if source:
                evidence.sources.add(source)
            handler = row["method_name"].strip()
            if handler:
                evidence.handlers.add(handler)
            method_counts[method] += 1
            continue

        extra_rows.append(
            {
                "classification": _extra_surface_class(interface_type, endpoint),
                "module_name": row["module_name"],
                "interface_type": interface_type,
                "endpoint": endpoint,
                "source_file_name": source,
                "method_name": row["method_name"],
                "parameters": row["parameters"],
                "interpretation": (
                    "inventoried separately; not compared as a direct HTTP server row"
                ),
            }
        )

    duplicate_rows = sum(count - 1 for count in exact_rows.values() if count > 1)
    return ParsedNoirts(
        row_total=len(rows),
        comparable=dict(comparable),
        extra_rows=extra_rows,
        interface_types=interface_counts,
        comparable_methods=method_counts,
        exact_duplicate_rows=duplicate_rows,
        source_styles=source_styles,
    )


def _all_sources(evidence: Mapping[Identity, IdentityEvidence]) -> set[str]:
    return {
        source
        for item in evidence.values()
        for source in item.sources
        if source
    }


def _suffix_source_mapping(
    absolute_sources: Iterable[str], relative_sources: Iterable[str]
) -> tuple[dict[str, str], int]:
    relatives = sorted(
        source for source in set(relative_sources) if source and not Path(source).is_absolute()
    )
    mapping: dict[str, str] = {}
    ambiguous = 0
    for absolute in sorted(set(absolute_sources)):
        if not Path(absolute).is_absolute():
            continue
        candidates = [
            relative
            for relative in relatives
            if absolute == relative or absolute.endswith("/" + relative)
        ]
        if len(candidates) == 1:
            mapping[absolute] = candidates[0]
        elif len(candidates) > 1:
            ambiguous += 1
    return mapping, ambiguous


def _replace_sources(
    evidence: Mapping[Identity, IdentityEvidence], mapping: Mapping[str, str]
) -> None:
    if not mapping:
        return
    for item in evidence.values():
        item.sources = {mapping.get(source, source) for source in item.sources}


def _align_source_evidence(
    noir: ParsedNoir, noirts: ParsedNoirts, source_root: Path | None
) -> dict[str, Any]:
    if source_root is not None:
        return {
            "mode": "explicit_source_root",
            "noir_sources_aligned": 0,
            "noirts_sources_aligned": 0,
            "ambiguous_suffix_sources": 0,
        }

    noir_sources = _all_sources(noir.comparable)
    noirts_sources = _all_sources(noirts.comparable)
    noir_mapping, noir_ambiguous = _suffix_source_mapping(
        noir_sources, noirts_sources
    )
    noirts_mapping, noirts_ambiguous = _suffix_source_mapping(
        noirts_sources, noir_sources
    )
    _replace_sources(noir.comparable, noir_mapping)
    _replace_sources(noirts.comparable, noirts_mapping)
    return {
        "mode": "automatic_exact_suffix_alignment",
        "noir_sources_aligned": len(noir_mapping),
        "noirts_sources_aligned": len(noirts_mapping),
        "ambiguous_suffix_sources": noir_ambiguous + noirts_ambiguous,
    }


def _source_relation(noir: set[str], noirts: set[str]) -> str:
    if not noir and not noirts:
        return "unavailable"
    if not noir:
        return "missing_in_noir"
    if not noirts:
        return "missing_in_noirts"
    if noir == noirts:
        return "equal"
    if noir < noirts:
        return "noir_subset"
    if noirts < noir:
        return "noirts_subset"
    if noir.isdisjoint(noirts):
        return "disjoint"
    return "overlap"


def _path_relation(noir_path: str, noirts_path: str) -> str:
    if noirts_path != noir_path and noirts_path.endswith(noir_path):
        return "noirts_path_has_noir_suffix"
    if noirts_path != noir_path and noir_path.endswith(noirts_path):
        return "noir_path_has_noirts_suffix"
    return "different"


def _path_disagreements(
    noir_only: Sequence[Identity],
    noirts_only: Sequence[Identity],
    noir_evidence: Mapping[Identity, IdentityEvidence],
    noirts_evidence: Mapping[Identity, IdentityEvidence],
) -> list[dict[str, Any]]:
    noir_groups: dict[tuple[str, str], set[Identity]] = defaultdict(set)
    noirts_groups: dict[tuple[str, str], set[Identity]] = defaultdict(set)
    for identity in noir_only:
        for source in noir_evidence[identity].sources:
            noir_groups[(source, identity.method)].add(identity)
    for identity in noirts_only:
        for source in noirts_evidence[identity].sources:
            noirts_groups[(source, identity.method)].add(identity)

    rows: list[dict[str, Any]] = []
    for source, method in sorted(set(noir_groups) & set(noirts_groups)):
        noir_group = sorted(noir_groups[(source, method)])
        noirts_group = sorted(noirts_groups[(source, method)])
        suffix_pairs: list[tuple[Identity, Identity, str]] = []
        for noir_identity in noir_group:
            for noirts_identity in noirts_group:
                relation = _path_relation(noir_identity.path, noirts_identity.path)
                if relation != "different":
                    suffix_pairs.append((noir_identity, noirts_identity, relation))

        selected_pairs = suffix_pairs
        if not selected_pairs and len(noir_group) == 1 and len(noirts_group) == 1:
            selected_pairs = [(noir_group[0], noirts_group[0], "different")]

        for noir_identity, noirts_identity, relation in selected_pairs:
            rows.append(
                {
                    "method": method,
                    "source": source,
                    "noir_path": noir_identity.path,
                    "noirts_path": noirts_identity.path,
                    "path_relation": relation,
                    "noir_endpoint_objects": noir_evidence[noir_identity].rows,
                    "noirts_evidence_rows": noirts_evidence[noirts_identity].rows,
                    "interpretation": (
                        "shared source and HTTP method with different reported paths; "
                        "inspect declarations before classifying detector recall"
                    ),
                }
            )
    return sorted(
        rows,
        key=lambda row: (
            row["method"],
            row["source"],
            row["noir_path"],
            row["noirts_path"],
        ),
    )


def _semantic_template_matches(
    noir_remaining: set[Identity],
    noirts_remaining: set[Identity],
    noir_evidence: Mapping[Identity, IdentityEvidence],
    noirts_evidence: Mapping[Identity, IdentityEvidence],
) -> tuple[
    list[tuple[Identity, Identity]],
    list[dict[str, Any]],
]:
    noir_groups: dict[tuple[str, str], list[Identity]] = defaultdict(list)
    noirts_groups: dict[tuple[str, str], list[Identity]] = defaultdict(list)
    for identity in sorted(noir_remaining):
        noir_groups[(identity.method, _template_shape(identity.path))].append(identity)
    for identity in sorted(noirts_remaining):
        noirts_groups[(identity.method, _template_shape(identity.path))].append(identity)

    matches: list[tuple[Identity, Identity]] = []
    ambiguous: list[dict[str, Any]] = []
    for method, shape in sorted(set(noir_groups) & set(noirts_groups)):
        noir_group = noir_groups[(method, shape)]
        noirts_group = noirts_groups[(method, shape)]
        # A placeholder-shape match is only corroborative when at least one
        # reported source file agrees. Without source overlap it is merely a
        # coincidental URI shape and must remain unmatched.
        if not any(
            noir_evidence[noir_identity].sources
            & noirts_evidence[noirts_identity].sources
            for noir_identity in noir_group
            for noirts_identity in noirts_group
        ):
            ambiguous.append(
                _ambiguous_template_row(
                    method,
                    shape,
                    noir_group,
                    noirts_group,
                    noir_evidence,
                    noirts_evidence,
                    "no_positive_source_overlap",
                )
            )
            continue
        smaller = min(len(noir_group), len(noirts_group))
        larger = max(len(noir_group), len(noirts_group))
        assignment_count = math.perm(larger, smaller)
        if assignment_count > 100_000:
            ambiguous.append(
                _ambiguous_template_row(
                    method,
                    shape,
                    noir_group,
                    noirts_group,
                    noir_evidence,
                    noirts_evidence,
                    "assignment_search_limit",
                )
            )
            continue

        assignments: list[tuple[tuple[int, int], tuple[tuple[Identity, Identity], ...]]] = []
        if len(noir_group) <= len(noirts_group):
            for selected in itertools.permutations(noirts_group, len(noir_group)):
                pairs = tuple(zip(noir_group, selected))
                assignments.append(
                    (_assignment_score(pairs, noir_evidence, noirts_evidence), pairs)
                )
        else:
            for selected in itertools.permutations(noir_group, len(noirts_group)):
                pairs = tuple(zip(selected, noirts_group))
                assignments.append(
                    (_assignment_score(pairs, noir_evidence, noirts_evidence), pairs)
                )

        best_score = max(score for score, _pairs in assignments)
        best = [pairs for score, pairs in assignments if score == best_score]
        if best_score[0] != min(len(noir_group), len(noirts_group)):
            ambiguous.append(
                _ambiguous_template_row(
                    method,
                    shape,
                    noir_group,
                    noirts_group,
                    noir_evidence,
                    noirts_evidence,
                    "assignment_contains_zero_source_overlap",
                )
            )
            continue
        if len(best) != 1:
            ambiguous.append(
                _ambiguous_template_row(
                    method,
                    shape,
                    noir_group,
                    noirts_group,
                    noir_evidence,
                    noirts_evidence,
                    "multiple_optimal_assignments",
                )
            )
            continue
        matches.extend(best[0])
    return sorted(matches), ambiguous


def _assignment_score(
    pairs: Iterable[tuple[Identity, Identity]],
    noir_evidence: Mapping[Identity, IdentityEvidence],
    noirts_evidence: Mapping[Identity, IdentityEvidence],
) -> tuple[int, int]:
    overlaps = [
        len(noir_evidence[noir].sources & noirts_evidence[noirts].sources)
        for noir, noirts in pairs
    ]
    return sum(overlap > 0 for overlap in overlaps), sum(overlaps)


def _ambiguous_template_row(
    method: str,
    shape: str,
    noir_group: Sequence[Identity],
    noirts_group: Sequence[Identity],
    noir_evidence: Mapping[Identity, IdentityEvidence],
    noirts_evidence: Mapping[Identity, IdentityEvidence],
    reason: str,
) -> dict[str, Any]:
    return {
        "method": method,
        "template_shape": shape,
        "noir_paths": _json_cell(identity.path for identity in noir_group),
        "noirts_paths": _json_cell(identity.path for identity in noirts_group),
        "noir_sources": _json_cell(
            source
            for identity in noir_group
            for source in noir_evidence[identity].sources
        ),
        "noirts_sources": _json_cell(
            source
            for identity in noirts_group
            for source in noirts_evidence[identity].sources
        ),
        "reason": reason,
        "interpretation": (
            "placeholder-shape overlap is ambiguous and remains unmatched"
        ),
    }


def _strict_status(
    *,
    noir_count: int,
    noirts_count: int,
    noir_only: int,
    noirts_only: int,
    semantic_matches: int,
) -> str:
    if noir_count == 0:
        return "no_comparable_noir_baseline"
    if noirts_count == 0:
        return "no_comparable_noirts_rows"
    if noir_only == 0 and noirts_only == 0:
        return (
            "semantic_identity_set_parity"
            if semantic_matches
            else "exact_identity_set_parity"
        )
    if noir_only == 0 and noirts_only > 0:
        return "covers_all_noir_and_adds_candidates"
    if noir_only > 0 and noirts_count > noir_count:
        return "more_total_but_still_noir_only"
    return "incomplete_overlap"


def _render_csv(fieldnames: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
        lineterminator="\n",
        extrasaction="raise",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _output_metadata(content: bytes, rows: int) -> dict[str, Any]:
    return {"bytes": len(content), "rows": rows, "sha256": _sha256_bytes(content)}


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _render_markdown(summary: Mapping[str, Any]) -> bytes:
    comparison = summary["comparison"]
    inventory = summary["inventory"]
    contract = summary["comparison_contract"]
    warnings = summary["warnings"]
    outputs = summary["outputs"]
    coverage = comparison["comparable_noir_baseline_coverage"]
    percent = (
        "n/a"
        if coverage["percent"] is None
        else f"{coverage['percent']:.2f}%"
    )
    lines = [
        "# Noir / noir-ts comparison",
        "",
        f"Strict status: `{comparison['strict_status']}`",
        "",
        (
            "The primary baseline is comparable direct HTTP server identities. "
            "noir-ts-only rows are **static candidates for review**, not proof that "
            "the endpoint is correct, registered, deployed, or runtime-reachable."
        ),
        "",
        "## Inputs",
        "",
        "| Report | Path | SHA-256 |",
        "|---|---|---|",
        (
            "| Noir JSON | "
            f"`{_markdown_cell(summary['inputs']['noir_json']['path'])}` | "
            f"`{summary['inputs']['noir_json']['sha256']}` |"
        ),
        (
            "| noir-ts CSV | "
            f"`{_markdown_cell(summary['inputs']['noirts_csv']['path'])}` | "
            f"`{summary['inputs']['noirts_csv']['sha256']}` |"
        ),
        "",
        "## Comparable HTTP server result",
        "",
        "| Metric | Count |",
        "|---|---:|",
        (
            "| Comparable Noir identities | "
            f"{inventory['noir']['comparable_http_server_identities']} |"
        ),
        (
            "| Comparable noir-ts identities | "
            f"{inventory['noirts']['comparable_http_server_identities']} |"
        ),
        (
            "| Exact identity matches | "
            f"{comparison['exact_matched_http_server_identities']} |"
        ),
        (
            "| Unique semantic-template matches | "
            f"{comparison['semantic_template_matched_http_server_identities']} |"
        ),
        (
            "| Total matched baseline identities | "
            f"{comparison['matched_http_server_identities']} |"
        ),
        (
            "| Source-corroborated matched identities | "
            f"{comparison['source_corroborated_matched_http_server_identities']} |"
        ),
        (
            "| Identity matches without source corroboration | "
            f"{comparison['identity_matches_without_source_corroboration']} |"
        ),
        (
            "| Noir-only identities | "
            f"{comparison['noir_only_http_server_identities']} |"
        ),
        (
            "| noir-ts-only candidates | "
            f"{comparison['noirts_only_http_server_candidates']} |"
        ),
        (
            "| noir-ts comparable identity count advantage | "
            f"{comparison['noirts_identity_count_advantage']:+d} |"
        ),
        (
            "| Comparable Noir baseline coverage | "
            f"{coverage['fraction']} ({percent}) |"
        ),
        (
            "| Ambiguous semantic-template clusters | "
            f"{comparison['ambiguous_template_clusters']} |"
        ),
        (
            "| Shared-source/method path disagreements | "
            f"{comparison['source_method_path_disagreements']} |"
        ),
        "",
        "Exact method/path identity is the primary match tier; regex constraints and "
        "unresolved placeholders remain significant. Only remaining rows can match "
        "by placeholder shape, and only when one best assignment gives every pair "
        "positive source overlap. Ambiguous clusters stay unmatched.",
        "",
        "## Scope inventories",
        "",
        "| Inventory | Count |",
        "|---|---:|",
        f"| Noir endpoint objects | {inventory['noir']['endpoint_objects']} |",
        (
            "| Noir endpoint objects outside comparable scope | "
            f"{inventory['noir']['noncomparable_endpoint_objects']} |"
        ),
        f"| noir-ts rows | {inventory['noirts']['rows']} |",
        (
            "| noir-ts extra-surface or invalid rows | "
            f"{inventory['noirts']['extra_surface_or_invalid_rows']} |"
        ),
        "",
        "Comparable noir-ts rows use the exact `http METHOD` interface form. "
        "WebSocket/messaging, outbound client, gateway, static-handler, unknown, "
        "and invalid rows remain in a separate inventory and do not inflate parity.",
        "",
        "## Contract",
        "",
        f"- Noir scope: {contract['noir_comparable_scope']}.",
        f"- Match rule: `{contract['match_rule']}`.",
        f"- Source comparison: `{contract['source_comparison']}`.",
        "- Query strings and fragments are removed; trailing slashes remain significant.",
        "",
        "## Warnings",
        "",
    ]
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None.")
    lines.extend(["", "## Output inventories", ""])
    for name in sorted(outputs):
        metadata = outputs[name]
        row_text = f", {metadata['rows']} data rows" if "rows" in metadata else ""
        lines.append(f"- `{name}` ({metadata['bytes']} bytes{row_text})")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def compare_reports(
    *,
    noir_path: Path,
    noirts_path: Path,
    output_dir: Path,
    technologies: frozenset[str],
    all_http_technologies: bool,
    source_root: Path | None,
) -> dict[str, Any]:
    noir = parse_noir_report(
        noir_path,
        technologies=technologies,
        all_http_technologies=all_http_technologies,
        source_root=source_root,
    )
    noirts = parse_noirts_report(noirts_path, source_root=source_root)

    source_alignment = _align_source_evidence(noir, noirts, source_root)
    noir_identities = set(noir.comparable)
    noirts_identities = set(noirts.comparable)
    exact_matches = sorted(noir_identities & noirts_identities)
    noir_remaining = noir_identities - set(exact_matches)
    noirts_remaining = noirts_identities - set(exact_matches)
    semantic_matches, ambiguous_templates = _semantic_template_matches(
        noir_remaining,
        noirts_remaining,
        noir.comparable,
        noirts.comparable,
    )
    noir_semantic = {noir_identity for noir_identity, _ in semantic_matches}
    noirts_semantic = {noirts_identity for _, noirts_identity in semantic_matches}
    noir_only = sorted(noir_remaining - noir_semantic)
    noirts_only = sorted(noirts_remaining - noirts_semantic)
    matched_pairs = [
        (identity, identity, "exact") for identity in exact_matches
    ] + [
        (noir_identity, noirts_identity, "semantic_template")
        for noir_identity, noirts_identity in semantic_matches
    ]
    matched_pairs.sort(key=lambda item: (item[0], item[1], item[2]))

    source_relations: Counter[str] = Counter()
    match_tiers: Counter[str] = Counter()
    matched_rows: list[dict[str, Any]] = []
    for noir_identity, noirts_identity, match_tier in matched_pairs:
        noir_evidence = noir.comparable[noir_identity]
        noirts_evidence = noirts.comparable[noirts_identity]
        relation = _source_relation(noir_evidence.sources, noirts_evidence.sources)
        source_relations[relation] += 1
        match_tiers[match_tier] += 1
        matched_rows.append(
            {
                "match_tier": match_tier,
                "method": noir_identity.method,
                "noir_path": noir_identity.path,
                "noirts_path": noirts_identity.path,
                "template_shape": _template_shape(noir_identity.path),
                "noir_endpoint_objects": noir_evidence.rows,
                "noirts_evidence_rows": noirts_evidence.rows,
                "noir_sources": _json_cell(noir_evidence.sources),
                "noirts_sources": _json_cell(noirts_evidence.sources),
                "source_relation": relation,
                "noir_technologies": _json_cell(noir_evidence.technologies),
                "noirts_handlers": _json_cell(noirts_evidence.handlers),
            }
        )

    noir_only_rows = [
        {
            "method": identity.method,
            "path": identity.path,
            "template_shape": _template_shape(identity.path),
            "noir_endpoint_objects": noir.comparable[identity].rows,
            "noir_sources": _json_cell(noir.comparable[identity].sources),
            "noir_technologies": _json_cell(
                noir.comparable[identity].technologies
            ),
            "interpretation": (
                "absent from the comparable noir-ts report; requires source and runtime review"
            ),
        }
        for identity in noir_only
    ]
    noirts_only_rows = [
        {
            "method": identity.method,
            "path": identity.path,
            "template_shape": _template_shape(identity.path),
            "noirts_evidence_rows": noirts.comparable[identity].rows,
            "noirts_sources": _json_cell(noirts.comparable[identity].sources),
            "noirts_handlers": _json_cell(noirts.comparable[identity].handlers),
            "interpretation": (
                "additional static candidate; not automatically correct or runtime-reachable"
            ),
        }
        for identity in noirts_only
    ]
    path_disagreements = _path_disagreements(
        noir_only,
        noirts_only,
        noir.comparable,
        noirts.comparable,
    )

    csv_outputs: dict[str, tuple[bytes, int]] = {
        MATCHED_OUTPUT_NAME: (
            _render_csv(
                (
                    "match_tier",
                    "method",
                    "noir_path",
                    "noirts_path",
                    "template_shape",
                    "noir_endpoint_objects",
                    "noirts_evidence_rows",
                    "noir_sources",
                    "noirts_sources",
                    "source_relation",
                    "noir_technologies",
                    "noirts_handlers",
                ),
                matched_rows,
            ),
            len(matched_rows),
        ),
        NOIR_ONLY_OUTPUT_NAME: (
            _render_csv(
                (
                    "method",
                    "path",
                    "template_shape",
                    "noir_endpoint_objects",
                    "noir_sources",
                    "noir_technologies",
                    "interpretation",
                ),
                noir_only_rows,
            ),
            len(noir_only_rows),
        ),
        NOIRTS_ONLY_OUTPUT_NAME: (
            _render_csv(
                (
                    "method",
                    "path",
                    "template_shape",
                    "noirts_evidence_rows",
                    "noirts_sources",
                    "noirts_handlers",
                    "interpretation",
                ),
                noirts_only_rows,
            ),
            len(noirts_only_rows),
        ),
        PATH_DISAGREEMENT_OUTPUT_NAME: (
            _render_csv(
                (
                    "method",
                    "source",
                    "noir_path",
                    "noirts_path",
                    "path_relation",
                    "noir_endpoint_objects",
                    "noirts_evidence_rows",
                    "interpretation",
                ),
                path_disagreements,
            ),
            len(path_disagreements),
        ),
        AMBIGUOUS_TEMPLATE_OUTPUT_NAME: (
            _render_csv(
                (
                    "method",
                    "template_shape",
                    "noir_paths",
                    "noirts_paths",
                    "noir_sources",
                    "noirts_sources",
                    "reason",
                    "interpretation",
                ),
                ambiguous_templates,
            ),
            len(ambiguous_templates),
        ),
        NOIRTS_EXTRA_OUTPUT_NAME: (
            _render_csv(
                (
                    "classification",
                    "module_name",
                    "interface_type",
                    "endpoint",
                    "source_file_name",
                    "method_name",
                    "parameters",
                    "interpretation",
                ),
                sorted(
                    noirts.extra_rows,
                    key=lambda row: tuple(
                        row[name]
                        for name in (
                            "classification",
                            "interface_type",
                            "endpoint",
                            "source_file_name",
                            "method_name",
                            "parameters",
                        )
                    ),
                ),
            ),
            len(noirts.extra_rows),
        ),
        NOIR_OUTPUT_NAME: (
            _render_csv(
                (
                    "reason",
                    "protocol",
                    "technology",
                    "method",
                    "url",
                    "canonical_path",
                    "sources",
                    "interpretation",
                ),
                sorted(
                    noir.noncomparable,
                    key=lambda row: tuple(
                        row[name]
                        for name in (
                            "reason",
                            "protocol",
                            "technology",
                            "method",
                            "url",
                            "sources",
                        )
                    ),
                ),
            ),
            len(noir.noncomparable),
        ),
    }

    warnings: list[str] = []
    internal_clients = sum(
        row["reason"] == "internal_client" for row in noir.noncomparable
    )
    if internal_clients:
        warnings.append(
            f"{internal_clients} Noir internal client endpoint object(s) were "
            "inventoried outside the direct inbound HTTP server denominator."
        )
    if noir.technology_fallback_used:
        warnings.append(
            "The Noir report has no technology metadata on any endpoint; HTTP rows "
            "were admitted via the explicit metadata-unavailable fallback."
        )
    elif any(row["reason"] == "technology:<none>" for row in noir.noncomparable):
        warnings.append(
            "The Noir report contains technology metadata, so individual HTTP rows "
            "without technology metadata were excluded from the Java denominator."
        )
    if all_http_technologies:
        warnings.append(
            "--all-noir-http broadens the Noir denominator beyond the default Java "
            "server technology allowlist."
        )
    if source_alignment["ambiguous_suffix_sources"]:
        warnings.append(
            "Some absolute/relative source paths had ambiguous suffix matches and "
            "were left unchanged; source relations may understate overlap."
        )
    if ambiguous_templates:
        warnings.append(
            "Ambiguous placeholder-shape clusters remain unmatched and are listed "
            f"in {AMBIGUOUS_TEMPLATE_OUTPUT_NAME}."
        )

    outputs = {
        name: _output_metadata(content, rows)
        for name, (content, rows) in sorted(csv_outputs.items())
    }
    matched_count = len(matched_pairs)
    source_corroborated_matches = sum(
        relation not in {"disjoint", "missing_in_noir", "missing_in_noirts", "unavailable"}
        for relation in (
            _source_relation(
                noir.comparable[noir_identity].sources,
                noirts.comparable[noirts_identity].sources,
            )
            for noir_identity, noirts_identity, _tier in matched_pairs
        )
    )
    noir_count = len(noir.comparable)
    noirts_count = len(noirts.comparable)
    coverage_percent = (
        round(100.0 * matched_count / noir_count, 2) if noir_count else None
    )
    strict_status = _strict_status(
        noir_count=noir_count,
        noirts_count=noirts_count,
        noir_only=len(noir_only),
        noirts_only=len(noirts_only),
        semantic_matches=len(semantic_matches),
    )
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "compare_noir_noirts", "version": TOOL_VERSION},
        "inputs": {
            "noir_json": _file_metadata(noir_path),
            "noirts_csv": _file_metadata(noirts_path),
        },
        "comparison_contract": {
            "identity_fields": ["method", "canonical_path"],
            "match_rule": "exact_then_unique_semantic_template",
            "exact_tier": (
                "exact method/path; regex constraints and unresolved placeholders are preserved"
            ),
            "semantic_tier": (
                "same method and placeholder shape; only a unique best assignment "
                "with positive source overlap for every pair"
            ),
            "ambiguous_semantic_clusters": "remain unmatched and are inventoried",
            "template_parameter_names_are_significant_in_exact_tier": True,
            "trailing_slash_is_significant": True,
            "absolute_http_url_rule": "remove scheme and authority for server-path comparison",
            "noirts_comparable_interface": "exact 'http METHOD' only",
            "noir_comparable_scope": (
                "all non-internal HTTP technologies"
                if all_http_technologies
                else (
                    "non-internal HTTP rows in the configured Java server "
                    "technology allowlist"
                )
            ),
            "noir_technologies": (
                [] if all_http_technologies else sorted(technologies)
            ),
            "noir_technology_metadata_available": (
                noir.technology_metadata_available
            ),
            "noir_technology_metadata_fallback_used": (
                noir.technology_fallback_used
            ),
            "source_comparison": (
                "source-root-relative"
                if source_root is not None
                else "normalized with conservative exact-suffix auto-alignment"
            ),
            "source_root": str(source_root) if source_root is not None else None,
            "source_alignment": source_alignment,
        },
        "inventory": {
            "noir": {
                "endpoint_objects": noir.endpoint_total,
                "passive_results": noir.passive_total,
                "comparable_http_server_endpoint_objects": sum(
                    evidence.rows for evidence in noir.comparable.values()
                ),
                "comparable_http_server_identities": len(noir.comparable),
                "comparable_source_occurrences": noir.comparable_source_occurrences,
                "noncomparable_endpoint_objects": len(noir.noncomparable),
                "technologies": _counter_dict(noir.technologies),
                "protocols": _counter_dict(noir.protocols),
                "methods": _counter_dict(noir.methods),
                "comparable_url_transforms": _counter_dict(noir.url_transforms),
                "technology_metadata_available": (
                    noir.technology_metadata_available
                ),
                "technology_metadata_fallback_used": (
                    noir.technology_fallback_used
                ),
            },
            "noirts": {
                "rows": noirts.row_total,
                "comparable_http_server_rows": sum(
                    evidence.rows for evidence in noirts.comparable.values()
                ),
                "comparable_http_server_identities": len(noirts.comparable),
                "extra_surface_or_invalid_rows": len(noirts.extra_rows),
                "exact_duplicate_rows": noirts.exact_duplicate_rows,
                "interface_types": _counter_dict(noirts.interface_types),
                "comparable_methods": _counter_dict(noirts.comparable_methods),
            },
        },
        "comparison": {
            "strict_status": strict_status,
            "exact_matched_http_server_identities": len(exact_matches),
            "semantic_template_matched_http_server_identities": len(
                semantic_matches
            ),
            "matched_http_server_identities": matched_count,
            "source_corroborated_matched_http_server_identities": (
                source_corroborated_matches
            ),
            "identity_matches_without_source_corroboration": (
                matched_count - source_corroborated_matches
            ),
            "noir_only_http_server_identities": len(noir_only),
            "noirts_only_http_server_candidates": len(noirts_only),
            "noirts_identity_count_advantage": noirts_count - noir_count,
            "comparable_noir_baseline_coverage": {
                "matched": matched_count,
                "denominator": noir_count,
                "fraction": f"{matched_count}/{noir_count}",
                "percent": coverage_percent,
            },
            "match_tiers": _counter_dict(match_tiers),
            "matched_source_relations": _counter_dict(source_relations),
            "ambiguous_template_clusters": len(ambiguous_templates),
            "source_method_path_disagreements": len(path_disagreements),
            "noir_overlap_fraction": f"{matched_count}/{noir_count}",
            "noirts_overlap_fraction": f"{matched_count}/{noirts_count}",
        },
        "interpretation": {
            "matched": (
                "present in both comparable reports by exact identity or an "
                "unambiguous semantic-template assignment; match_tier and "
                "source_relation preserve the distinction"
            ),
            "noir_only": (
                "absent from the comparable noir-ts report; investigate before calling it a miss"
            ),
            "noirts_only": (
                "additional static candidates, not automatically correct, deployed, or runtime-reachable"
            ),
            "extra_surfaces": (
                "inventoried outside the direct HTTP server denominator; not cross-tool wins or losses"
            ),
            "strict_status": (
                "distinguishes complete Noir-baseline coverage plus candidates from "
                "a larger noir-ts total that still leaves Noir-only identities"
            ),
            "path_disagreements": (
                "diagnostic only: unmatched rows share source and method but report "
                "different paths; this is not an automatic equivalence"
            ),
        },
        "warnings": warnings,
        "outputs": outputs,
    }

    markdown_content = _render_markdown(summary)
    summary["outputs"][REPORT_OUTPUT_NAME] = {
        "bytes": len(markdown_content),
        "sha256": _sha256_bytes(markdown_content),
    }
    summary_content = (
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    output_parent = output_dir.resolve(strict=False).parent
    output_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.staging-", dir=output_parent
        )
    )
    try:
        for name, (content, _rows) in sorted(csv_outputs.items()):
            (staging / name).write_bytes(content)
        (staging / REPORT_OUTPUT_NAME).write_bytes(markdown_content)
        (staging / SUMMARY_OUTPUT_NAME).write_bytes(summary_content)
        output_dir.mkdir(parents=True, exist_ok=True)
        expected_names = {
            *csv_outputs,
            REPORT_OUTPUT_NAME,
            SUMMARY_OUTPUT_NAME,
        }
        for stale in sorted(output_dir.iterdir()):
            if stale.is_file() and stale.name not in expected_names:
                stale.unlink()
        for name in sorted(expected_names):
            (staging / name).replace(output_dir / name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return summary


def build_argument_parser() -> argparse.ArgumentParser:
    script_path = Path(__file__).resolve(strict=False)
    parser = argparse.ArgumentParser(
        description=(
            "Compare direct Java HTTP server identities in OWASP Noir JSON "
            "(verified with 0.29.x and 1.2.1) and noir-ts semicolon CSV while "
            "inventorying client and other surfaces separately."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=rf"""copy-paste example (replace the three /path values):
  COMPARISON_DIR="$(mktemp -d /tmp/noir-noirts.XXXXXX)"
  PYTHONDONTWRITEBYTECODE=1 python3 -B \
    "{script_path}" \
    "/path/to/noir-report.json" \
    "/path/to/noir-ts-report.csv" \
    --source-root "/path/to/analyzed-source" \
    --output-dir "$COMPARISON_DIR"
  sed -n '1,240p' "$COMPARISON_DIR/comparison.md"

produce the required monolithic JSON with OWASP Noir 0.29.x:
  NOIR_JSON="$(mktemp --suffix=.json /tmp/noir-0.29.XXXXXX)"
  noir -b "/path/to/analyzed-source" --format json \
    --output "$NOIR_JSON" --no-log --no-color

JSONL, YAML, and log/console output are not valid NOIR_JSON inputs.""",
    )
    parser.add_argument(
        "noir_json",
        type=Path,
        help="OWASP Noir --format json report (verified: 0.29.x and 1.2.1)",
    )
    parser.add_argument("noirts_csv", type=Path, help="noir-ts semicolon CSV report")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("comparison-noir-noirts"),
        help=(
            "directory for deterministic JSON, Markdown, and CSV outputs "
            "(default: ./comparison-noir-noirts)"
        ),
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        help=(
            "optional analyzed source root; absolute and relative source evidence "
            "is normalized relative to this directory"
        ),
    )
    parser.add_argument(
        "--noir-technology",
        action="append",
        dest="noir_technologies",
        metavar="NAME",
        help=(
            "comparable Noir HTTP technology; repeat as needed. Defaults to "
            "java_jaxrs, java_quarkus, and java_spring"
        ),
    )
    parser.add_argument(
        "--all-noir-http",
        action="store_true",
        help="compare every Noir HTTP technology (broader and less conservative)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    if args.all_noir_http and args.noir_technologies:
        parser.error("--all-noir-http cannot be combined with --noir-technology")
    technologies = frozenset(
        args.noir_technologies or DEFAULT_NOIR_TECHNOLOGIES
    )
    source_root = (
        args.source_root.resolve(strict=False) if args.source_root is not None else None
    )
    try:
        summary = compare_reports(
            noir_path=args.noir_json,
            noirts_path=args.noirts_csv,
            output_dir=args.output_dir,
            technologies=technologies,
            all_http_technologies=args.all_noir_http,
            source_root=source_root,
        )
    except ComparatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    comparison = summary["comparison"]
    inventory = summary["inventory"]
    print(f"summary={args.output_dir / SUMMARY_OUTPUT_NAME}")
    print(f"strict_status={comparison['strict_status']}")
    print(
        "matched_http_server_identities="
        f"{comparison['matched_http_server_identities']}"
    )
    print(
        "noir_only_http_server_identities="
        f"{comparison['noir_only_http_server_identities']}"
    )
    print(
        "noirts_only_http_server_candidates="
        f"{comparison['noirts_only_http_server_candidates']}"
    )
    print(
        "noirts_extra_surface_or_invalid_rows="
        f"{inventory['noirts']['extra_surface_or_invalid_rows']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
