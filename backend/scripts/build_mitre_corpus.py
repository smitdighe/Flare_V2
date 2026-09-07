"""Extract the MITRE ATT&CK corpus from the official STIX bundle.

PLAN §4.4 / D5. Output is one JSON file per technique in `app/rag/corpus/`,
COMMITTED, Pydantic-validated by `app/rag/loader.py` at load. Nothing is fetched
at runtime.

Source: https://github.com/mitre-attack/attack-stix-data — MITRE's own
publication, ATT&CK Terms of Use, free.

WHY A SUBSET AND NOT ALL 858 TECHNIQUES. Retrieval has to discriminate, and a
corpus dominated by techniques nothing in this pipeline can ever produce
(macOS persistence, cloud IAM abuse) adds noise without adding a right answer.
The selection covers every technique the six canonical classes actually map to,
plus the neighbouring techniques a wrong-but-plausible retrieval would return —
so the labelled recall@k set is measuring real discrimination rather than
picking from a field of one.

ATT&CK v19 dropped the free-text `x_mitre_detection` field in favour of linked
detection-strategy objects. Detection text is therefore assembled from those
relationships rather than read off the technique, and is empty where none are
linked. Mitigations come from `mitigates` relationships to course-of-action
objects.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.rag.loader import CORPUS_DIR, MANIFEST_NAME, Technique, corpus_hash

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Grouped by the canonical class each set serves. The comment is the reason the
# group exists; a technique with no reason to be here is noise in the index.
SELECTED: dict[str, tuple[str, ...]] = {
    # dos / ddos
    "impact": (
        "T1498", "T1498.001", "T1498.002",
        "T1499", "T1499.001", "T1499.002", "T1499.003", "T1499.004",
        "T1489", "T1496",
    ),
    # port_scan
    "discovery": (
        "T1046", "T1595", "T1595.001", "T1595.002",
        "T1018", "T1049", "T1590", "T1590.005", "T1016", "T1135",
    ),
    # botnet — C2 and the infrastructure behind it
    "command_and_control": (
        "T1071", "T1071.001", "T1071.004",
        "T1102", "T1568", "T1568.002", "T1573", "T1573.001", "T1573.002",
        "T1090", "T1095", "T1105", "T1008", "T1583.005", "T1584.005", "T1219",
    ),
    # web_attack
    "initial_access_and_execution": (
        "T1190", "T1189", "T1133", "T1078",
        "T1059.007", "T1505.003", "T1211", "T1212",
        "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004",
    ),
    # neighbours a plausible-but-wrong retrieval would reach for; they make
    # recall@k a real measurement rather than a formality
    "adjacent": (
        "T1040", "T1021", "T1021.001", "T1041", "T1030", "T1048",
        "T1566", "T1204", "T1027", "T1553", "T1550", "T1136",
    ),
}


def flatten(selection: dict[str, tuple[str, ...]]) -> list[str]:
    seen: list[str] = []
    for group in selection.values():
        for technique_id in group:
            if technique_id not in seen:
                seen.append(technique_id)
    return seen


def load_bundle(path: Path | None) -> dict[str, Any]:
    if path and path.exists():
        print(f"Reading {path} ...")
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data

    print(f"Downloading {STIX_URL} (~54 MB) ...", flush=True)
    with urllib.request.urlopen(STIX_URL, timeout=300) as response:
        payload: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    return payload


def external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            identifier: str = reference["external_id"]
            return identifier
    return None


def external_url(obj: dict[str, Any]) -> str:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            url: str = reference.get("url", "")
            return url
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", type=Path, help="a local enterprise-attack.json")
    parser.add_argument("--out-dir", type=Path, default=CORPUS_DIR)
    args = parser.parse_args()

    bundle = load_bundle(args.stix)
    objects: list[dict[str, Any]] = bundle["objects"]

    attack_version = "unknown"
    attack_spec = "unknown"
    for obj in objects:
        if obj["type"] == "x-mitre-collection":
            attack_version = str(obj.get("x_mitre_version", "unknown"))
            attack_spec = str(obj.get("x_mitre_attack_spec_version", "unknown"))
            break

    by_stix_id = {obj["id"]: obj for obj in objects}
    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj["type"] == "attack-pattern" and not obj.get("revoked"):
            identifier = external_id(obj)
            if identifier:
                techniques[identifier] = obj

    # mitigates: course-of-action -> technique. detects: detection-strategy ->
    # technique. Both are relationships in v19, not fields on the technique.
    mitigations: dict[str, list[str]] = defaultdict(list)
    detections: dict[str, list[str]] = defaultdict(list)
    for obj in objects:
        if obj["type"] != "relationship":
            continue
        source_obj = by_stix_id.get(obj.get("source_ref", ""))
        target = obj.get("target_ref", "")
        if source_obj is None or target not in by_stix_id:
            continue
        source: dict[str, Any] = source_obj
        target_id = external_id(by_stix_id[target])
        if target_id is None:
            continue
        if obj["relationship_type"] == "mitigates" and source["type"] == "course-of-action":
            mitigations[target_id].append(source["name"])
        elif obj["relationship_type"] == "detects":
            text = source.get("description") or source.get("name") or ""
            if text:
                detections[target_id].append(str(text))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for stale in args.out_dir.glob("T*.json"):
        stale.unlink()

    wanted = flatten(SELECTED)
    missing = [t for t in wanted if t not in techniques]
    if missing:
        print(f"  WARNING: not present in this ATT&CK release: {missing}")

    written = 0
    for technique_id in wanted:
        found = techniques.get(technique_id)
        if found is None:
            continue
        technique_obj: dict[str, Any] = found

        tactics = [
            phase["phase_name"].replace("-", " ")
            for phase in technique_obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        if not tactics:
            print(f"  skipping {technique_id}: no mitre-attack kill chain phase")
            continue

        parent = technique_id.split(".")[0] if "." in technique_id else None

        technique = Technique(
            technique_id=technique_id,
            name=technique_obj["name"],
            description=technique_obj.get("description", ""),
            tactics=tactics,
            platforms=list(technique_obj.get("x_mitre_platforms", [])),
            mitigations=sorted(set(mitigations.get(technique_id, []))),
            detection=" ".join(detections.get(technique_id, []))[:4000],
            is_subtechnique=bool(technique_obj.get("x_mitre_is_subtechnique", False)),
            parent_id=parent,
            url=external_url(technique_obj),
            attack_version=attack_version,
        )
        (args.out_dir / f"{technique_id}.json").write_text(
            technique.model_dump_json(indent=2), encoding="utf-8"
        )
        written += 1

    manifest = {
        "attack_version": attack_version,
        "attack_spec": attack_spec,
        "source": STIX_URL,
        "technique_count": written,
        "corpus_sha256": corpus_hash(args.out_dir),
        "built_at": datetime.now(UTC).isoformat(),
    }
    (args.out_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nWrote {written} techniques to {args.out_dir}")
    print(f"  ATT&CK version {attack_version} (spec {attack_spec})")
    print(f"  corpus sha256 {manifest['corpus_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
