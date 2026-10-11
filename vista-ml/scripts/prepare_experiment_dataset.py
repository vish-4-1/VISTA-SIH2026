from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vista_ml.features.pcap_features import extract_flow_features  # noqa: E402

SCHEMA_VERSION = "vista-strongswan-experiment-v1"
SCHEMA_VERSION_V2 = "vista-strongswan-experiment-v2"
FEATURE_SCHEMA_PATH = ROOT / "schemas" / "vista-flow-v1.json"
MANIFEST_SCHEMA_PATH = ROOT / "schemas" / "strongswan-experiment-manifest-v1.schema.json"
MANIFEST_SCHEMA_V2_PATH = ROOT / "schemas" / "strongswan-experiment-manifest-v2.schema.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classic_pcap_packet_count(path: Path, protocol_family: str | None = None) -> int:
    with path.open("rb") as stream:
        global_header = stream.read(24)
        if len(global_header) != 24:
            raise ValueError("truncated classic-PCAP global header")
        magic = global_header[:4]
        byte_order = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\xa1\xb2\x3c\x4d": ">",
        }.get(magic)
        if byte_order is None:
            raise ValueError("unsupported classic-PCAP magic")
        major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack(
            f"{byte_order}HHIIII", global_header[4:]
        )
        if (major, minor) != (2, 4) or snaplen <= 0:
            raise ValueError("invalid classic-PCAP version or snapshot length")
        packets = 0
        observed_protocols: set[str] = set()
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError("truncated classic-PCAP packet header")
            _seconds, _fraction, captured_length, original_length = struct.unpack(
                f"{byte_order}IIII", packet_header
            )
            if captured_length > snaplen or captured_length > original_length:
                raise ValueError("classic-PCAP packet length exceeds its header limits")
            packet = stream.read(captured_length)
            if len(packet) != captured_length:
                raise ValueError("truncated classic-PCAP packet data")
            network_offset = None
            ether_type = None
            if link_type == 1 and len(packet) >= 14:
                ether_type = int.from_bytes(packet[12:14], "big")
                network_offset = 14
                while ether_type in {0x8100, 0x88A8} and len(packet) >= network_offset + 4:
                    ether_type = int.from_bytes(packet[network_offset + 2:network_offset + 4], "big")
                    network_offset += 4
            elif link_type == 101:
                ether_type = 0x0800 if packet and packet[0] >> 4 == 4 else None
                network_offset = 0
            elif link_type == 113 and len(packet) >= 16:
                ether_type = int.from_bytes(packet[14:16], "big")
                network_offset = 16
            elif link_type == 276 and len(packet) >= 20:
                ether_type = int.from_bytes(packet[:2], "big")
                network_offset = 20
            if (
                ether_type == 0x0800
                and network_offset is not None
                and len(packet) > network_offset + 9
                and packet[network_offset] >> 4 == 4
            ):
                ip_protocol = packet[network_offset + 9]
                observed_protocols.add({1: "ICMP", 6: "TCP", 17: "UDP", 50: "ESP"}.get(
                    ip_protocol, "OTHER"
                ))
                if ip_protocol == 17:
                    ip_header_length = (packet[network_offset] & 0x0F) * 4
                    udp_offset = network_offset + ip_header_length
                    if len(packet) >= udp_offset + 16:
                        source_port, destination_port = struct.unpack(
                            ">HH", packet[udp_offset:udp_offset + 4]
                        )
                        udp_payload = packet[udp_offset + 8:udp_offset + 16]
                        if (
                            (source_port == 4500 or destination_port == 4500)
                            and len(udp_payload) == 8
                            and udp_payload[:4] != b"\x00\x00\x00\x00"
                        ):
                            observed_protocols.add("ESP")
            packets += 1
        if packets == 0:
            raise ValueError("classic-PCAP contains no packets")
        if protocol_family and protocol_family not in observed_protocols:
            raise ValueError(
                f"classic-PCAP contains no IPv4 {protocol_family} packets"
            )
        return packets


def _member_path(base: Path, value: Any, description: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{description} must be a non-empty relative path.")
    relative = Path(value)
    if relative.is_absolute() or (relative.drive and relative.drive != ""):
        raise ValueError(f"{description} must be relative to the manifest.")
    resolved = (base / relative).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise ValueError(f"{description} escapes the manifest directory.") from exc
    return resolved


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, dict):
        forbidden = {"psk", "password", "privatekey", "secret", "credential"}
        return any(
            "".join(
                character for character in str(key).casefold() if character.isalnum()
            ) in forbidden or _contains_secret_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


def validate_manifest_shape(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict):
        raise ValueError("Manifest root must be a JSON object.")
    manifest_version = manifest.get("manifest_version")
    if manifest_version not in {SCHEMA_VERSION, SCHEMA_VERSION_V2}:
        raise ValueError(
            f"manifest_version must equal {SCHEMA_VERSION!r} or {SCHEMA_VERSION_V2!r}."
        )
    if not isinstance(manifest.get("dataset_id"), str) or not manifest["dataset_id"].strip():
        raise ValueError("dataset_id must be a non-empty string.")
    if manifest.get("feature_schema_version") != "vista-flow-v1":
        raise ValueError("feature_schema_version must equal 'vista-flow-v1'.")
    if not isinstance(manifest.get("extractor_version"), str) or not manifest["extractor_version"]:
        raise ValueError("extractor_version must be a non-empty string.")
    unknown_root = sorted(
        manifest.keys()
        - {"manifest_version", "dataset_id", "feature_schema_version", "extractor_version", "observations"}
    )
    if unknown_root:
        raise ValueError(f"Manifest has unsupported root fields: {unknown_root}")
    if _contains_secret_key(manifest):
        raise ValueError("Manifest contains a prohibited secret/credential field; provide redacted evidence.")
    observations = manifest.get("observations")
    if not isinstance(observations, list):
        raise ValueError("observations must be a JSON array.")
    errors = []
    required_top = {
        "experiment_id", "session_id", "capture", "ground_truth",
        "workload", "vpn", "data_quality",
    }
    if manifest_version == SCHEMA_VERSION_V2:
        required_top |= {"session_record_path", "session_record_sha256"}
    required_nested = {
        "capture": {
            "path", "format", "sha256", "started_at", "interface",
            "capture_point", "ip_version", "protocol_family",
        },
        "ground_truth": {
            "label", "record_path", "record_sha256", "record_field", "method",
            "independently_verified",
        },
        "workload": {"type", "configuration"},
        "vpn": {
            "requested_configuration", "effective_configuration",
            "negotiated_sa_evidence_path", "negotiated_sa_evidence_sha256",
        },
        "data_quality": {"status", "reasons"},
    }
    if manifest_version == SCHEMA_VERSION_V2:
        required_nested["capture"] |= {
            "completed_at", "raw_pcap_path", "raw_pcap_format", "raw_pcap_sha256",
            "raw_pcap_size_bytes",
        }
        required_nested["workload"] |= {"measurement_path", "measurement_sha256"}

    allowed_nested = {k: set(v) for k, v in required_nested.items()}
    if manifest_version == SCHEMA_VERSION_V2:
        allowed_nested["workload"] |= {"subtype"}
        allowed_nested["ground_truth"] |= {"label_schema_version", "workload_subtype"}

    for index, raw in enumerate(observations):
        prefix = f"observations[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{prefix}:entry_not_object")
            continue
        missing = sorted(required_top - raw.keys())
        if missing:
            errors.append(f"{prefix}:missing_fields:{','.join(missing)}")
        unknown = sorted(raw.keys() - required_top)
        if unknown:
            errors.append(f"{prefix}:unknown_fields:{','.join(unknown)}")
        for field in ("experiment_id", "session_id"):
            if not isinstance(raw.get(field), str) or not raw[field].strip():
                errors.append(f"{prefix}:invalid_{field}")
        if manifest_version == SCHEMA_VERSION_V2:
            for field in ("session_record_path", "session_record_sha256"):
                if not isinstance(raw.get(field), str) or not raw[field].strip():
                    errors.append(f"{prefix}:invalid_{field}")
            for field in ("experiment_id", "session_id"):
                try:
                    if uuid.UUID(raw[field]).version != 4:
                        raise ValueError("not_uuid4")
                except (ValueError, TypeError, AttributeError):
                    errors.append(f"{prefix}:invalid_uuid4_{field}")
        for field in ("capture", "ground_truth", "workload", "vpn", "data_quality"):
            nested = raw.get(field)
            if not isinstance(nested, dict):
                errors.append(f"{prefix}:invalid_{field}_object")
                continue
            nested_missing = sorted(required_nested[field] - nested.keys())
            if nested_missing:
                errors.append(
                    f"{prefix}:missing_{field}_fields:{','.join(nested_missing)}"
                )
            nested_unknown = sorted(nested.keys() - allowed_nested[field])
            if nested_unknown:
                errors.append(
                    f"{prefix}:unknown_{field}_fields:{','.join(nested_unknown)}"
                )
    return errors


def _identifier_contains_label(identifier: str, label: str) -> bool:
    normalize = lambda value: re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    identifier_tokens = f"_{normalize(identifier)}_"
    label_token = normalize(label)
    return bool(label_token and f"_{label_token}_" in identifier_tokens)


def _observation_features(
    observation: dict,
    manifest_dir: Path,
    feature_columns: list[str],
    manifest_version: str,
) -> tuple[dict | None, list[str]]:
    errors: list[str] = []
    experiment_id = observation.get("experiment_id", "")
    session_id = observation.get("session_id", "")
    capture = observation.get("capture", {})
    truth = observation.get("ground_truth", {})
    vpn = observation.get("vpn", {})
    quality = observation.get("data_quality", {})

    label = truth.get("label")
    if not isinstance(label, str) or not label.strip():
        errors.append("missing_explicit_ground_truth_label")
    else:
        if any(
            _identifier_contains_label(identifier, label)
            for identifier in (experiment_id, session_id, capture.get("path", ""))
            if isinstance(identifier, str)
        ):
            errors.append("identifier_or_filename_contains_target_label")

    capture_path = None
    truth_path = None
    vpn_path = None
    session_path = None
    measurement_path = None
    independent_session_key = None
    try:
        capture_path = _member_path(manifest_dir, capture.get("path"), "capture.path")
        truth_path = _member_path(
            manifest_dir, truth.get("record_path"), "ground_truth.record_path"
        )
        vpn_path = _member_path(
            manifest_dir,
            vpn.get("negotiated_sa_evidence_path"),
            "vpn.negotiated_sa_evidence_path",
        )
        if manifest_version == SCHEMA_VERSION_V2:
            session_path = _member_path(
                manifest_dir, observation.get("session_record_path"),
                "session_record_path",
            )
            measurement_path = _member_path(
                manifest_dir, observation.get("workload", {}).get("measurement_path"),
                "workload.measurement_path",
            )
    except ValueError as exc:
        errors.append(f"invalid_manifest_path:{exc}")

    for description, path, field in (
        ("capture", capture_path, "sha256"),
        ("ground_truth_record", truth_path, "record_sha256"),
        ("negotiated_sa_evidence", vpn_path, "negotiated_sa_evidence_sha256"),
    ):
        if path is None:
            continue
        if not path.is_file():
            errors.append(f"missing_{description}_file")
            continue
        expected = capture.get(field) if description == "capture" else (
            truth.get(field) if description == "ground_truth_record"
            else vpn.get(field)
        )
        if not isinstance(expected, str) or sha256_file(path) != expected:
            errors.append(f"{description}_sha256_mismatch")

    if manifest_version == SCHEMA_VERSION_V2:
        for description, path, expected in (
            ("session_record", session_path, observation.get("session_record_sha256")),
            (
                "workload_measurement",
                measurement_path,
                observation.get("workload", {}).get("measurement_sha256"),
            ),
        ):
            if path is None:
                continue
            if not path.is_file():
                errors.append(f"missing_{description}_file")
            elif not isinstance(expected, str) or sha256_file(path) != expected:
                errors.append(f"{description}_sha256_mismatch")

        capture_pcap = None
        try:
            capture_pcap = _member_path(
                manifest_dir, capture.get("raw_pcap_path"), "capture.raw_pcap_path"
            )
        except ValueError as exc:
            errors.append(f"invalid_manifest_path:{exc}")
        if capture_pcap is not None:
            if not capture_pcap.is_file():
                errors.append("missing_raw_pcap_file")
            else:
                try:
                    classic_pcap_packet_count(
                        capture_pcap, capture.get("protocol_family")
                    )
                except (OSError, ValueError) as exc:
                    errors.append(f"raw_pcap_unreadable:{exc}")
                if capture_pcap.stat().st_size != capture.get("raw_pcap_size_bytes"):
                    errors.append("raw_pcap_size_mismatch")
                if sha256_file(capture_pcap) != capture.get("raw_pcap_sha256"):
                    errors.append("raw_pcap_sha256_mismatch")
        if capture.get("raw_pcap_format") != "pcap":
            errors.append("unsupported_raw_pcap_format")
        if session_path and session_path.is_file():
            try:
                session_record = json.loads(session_path.read_text(encoding="utf-8"))
                if not isinstance(session_record, dict):
                    raise ValueError("session record root must be an object")
                if session_record.get("sessionId") != session_id:
                    errors.append("session_record_does_not_support_session_id")
                if session_record.get("sessionIdSource") is None:
                    errors.append("session_id_provenance_missing")
                lifecycle = session_record.get("vpnLifecycle", {})
                if not isinstance(lifecycle, dict):
                    lifecycle = {}
                reestablishment = lifecycle.get("reestablishment", {})
                if not isinstance(reestablishment, dict):
                    reestablishment = {}
                container_ids = session_record.get("containerIds", {})
                if not isinstance(container_ids, dict):
                    container_ids = {}
                identity = lifecycle.get("ikeSaIdentitySha256")
                age = lifecycle.get("ikeSaAgeSeconds")
                session_started = session_record.get("sessionStartedAt")
                session_observed = session_record.get("sessionObservedThroughAt")
                try:
                    parsed_session_started = datetime.fromisoformat(
                        session_started.replace("Z", "+00:00")
                    )
                    parsed_session_observed = datetime.fromisoformat(
                        session_observed.replace("Z", "+00:00")
                    )
                    parsed_reestablished = datetime.fromisoformat(
                        str(reestablishment.get("reestablishedAt", "")).replace(
                            "Z", "+00:00"
                        )
                    )
                    valid_session_times = (
                        parsed_session_started.tzinfo is not None
                        and parsed_session_observed.tzinfo is not None
                        and parsed_reestablished.tzinfo is not None
                        and parsed_session_started <= parsed_session_observed
                        and parsed_reestablished <= parsed_session_started
                        and (
                            parsed_session_started - parsed_reestablished
                        ).total_seconds() <= 60
                    )
                except (AttributeError, TypeError, ValueError):
                    valid_session_times = False
                if (
                    reestablishment.get("independenceStatus")
                    != "VERIFIED_DISTINCT_IKE_SA"
                    or not isinstance(identity, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", identity)
                    or reestablishment.get("ikeSaIdentitySha256") != identity
                    or isinstance(age, bool)
                    or not isinstance(age, int)
                    or age > 60
                    or reestablishment.get("previousIkeSaIdentitySha256") == identity
                    or set(container_ids) != {"pc1", "pc2"}
                    or any(not isinstance(value, str) or not value for value in container_ids.values())
                    or not isinstance(session_record.get("experimentIds"), list)
                    or experiment_id not in session_record.get("experimentIds", [])
                    or not valid_session_times
                ):
                    errors.append("session_independence_unverified")
                else:
                    independent_session_key = identity
            except (json.JSONDecodeError, OSError, ValueError):
                errors.append("session_record_is_not_valid_json")
        if measurement_path and measurement_path.is_file():
            try:
                measurement = json.loads(measurement_path.read_text(encoding="utf-8"))
                if (
                    measurement.get("experimentId") != experiment_id
                    or measurement.get("sessionId") != session_id
                ):
                    errors.append("workload_measurement_ids_do_not_match_manifest")
            except (json.JSONDecodeError, OSError):
                errors.append("workload_measurement_is_not_valid_json")
    else:
        errors.append("session_independence_unverified:legacy_manifest_has_no_verified_sa_lifecycle")

    if truth_path and truth_path.is_file() and isinstance(label, str):
        try:
            truth_record = json.loads(truth_path.read_text(encoding="utf-8"))
            field = truth.get("record_field")
            if not isinstance(field, str) or truth_record.get(field) != label:
                errors.append("ground_truth_record_does_not_support_manifest_label")
        except (json.JSONDecodeError, OSError):
            errors.append("ground_truth_record_is_not_valid_json")

    try:
        started_at = capture.get("started_at")
        if not isinstance(started_at, str):
            raise ValueError("capture timestamp is absent")
        parsed_started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        if parsed_started_at.tzinfo is None:
            raise ValueError("capture timestamp has no timezone")
    except ValueError:
        errors.append("capture_timestamp_missing_or_invalid")

    if capture.get("format") != "packet_table_csv":
        errors.append("unsupported_capture_format")
    if capture.get("ip_version") != 4:
        errors.append("unsupported_ip_version_for_vista_flow_v1")
    if not capture.get("interface") or capture.get("capture_point") not in {"outer", "inner"}:
        errors.append("capture_interface_or_point_unverified")
    if not capture.get("protocol_family"):
        errors.append("capture_protocol_family_missing")
    if truth.get("independently_verified") is not True:
        errors.append("ground_truth_not_independently_verified")
    if quality.get("status") != "accepted" or quality.get("reasons"):
        errors.extend(
            str(reason) for reason in quality.get("reasons", [])
            if str(reason)
        )
        if not quality.get("reasons"):
            errors.append("manifest_marks_observation_quarantined")
    if vpn.get("effective_configuration") is None:
        errors.append("effective_vpn_configuration_missing")
    if not vpn.get("requested_configuration"):
        errors.append("requested_vpn_configuration_missing")

    if capture_path and capture_path.is_file() and not any(
        reason.startswith("capture_sha256") for reason in errors
    ):
        try:
            packets = pd.read_csv(capture_path)
            protocol_column = "protocol_family" if "protocol_family" in packets else "protocol"
            if protocol_column not in packets or packets.empty:
                errors.append("packet_table_empty_or_missing_protocol")
            else:
                observed = {
                    str(value).strip().casefold()
                    for value in packets[protocol_column].dropna().unique()
                }
                expected = str(capture.get("protocol_family", "")).strip().casefold()
                if observed != {expected}:
                    errors.append("packet_table_protocol_does_not_match_manifest")
            features = extract_flow_features(packets)
            if len(features) != 1:
                errors.append("packet_table_did_not_produce_exactly_one_flow")
            elif not errors:
                numeric = features.loc[:, feature_columns].apply(pd.to_numeric, errors="coerce")
                values = numeric.to_numpy(dtype=float)
                if not np.isfinite(values).all():
                    errors.append("feature_extraction_produced_missing_or_nonfinite_values")
                elif (values < 0).any():
                    errors.append("feature_extraction_produced_negative_values")
                else:
                    return (
                        {
                            "experiment_id": experiment_id,
                            "session_id": session_id,
                            "_independent_session_key": independent_session_key,
                            "label": label,
                            "capture_path": str(capture_path.relative_to(manifest_dir)),
                            "capture_sha256": capture["sha256"],
                            **dict(zip(feature_columns, values[0].tolist())),
                        },
                        errors,
                    )
        except (OSError, ValueError, pd.errors.ParserError) as exc:
            errors.append(f"packet_table_or_feature_extraction_error:{exc}")

    return None, errors


def _duplicate_flags(rows: list[dict], feature_columns: list[str]) -> tuple[dict[str, list[str]], list[dict]]:
    quarantined: dict[str, list[str]] = {}
    hash_groups: dict[str, list[str]] = {}
    for row in rows:
        hash_groups.setdefault(row["capture_sha256"], []).append(row["experiment_id"])
    for group in hash_groups.values():
        if len(group) > 1:
            for experiment_id in group:
                quarantined.setdefault(experiment_id, []).append(
                    f"duplicate_capture_hash_group:{','.join(sorted(group))}"
                )
    values = np.asarray(
        [[row[column] for column in feature_columns] for row in rows], dtype=float
    )
    near_pairs = []
    for left in range(len(rows)):
        for right in range(left + 1, len(rows)):
            scale = np.maximum(np.maximum(np.abs(values[left]), np.abs(values[right])), 1.0)
            delta = np.abs(values[left] - values[right]) / scale
            if np.all(delta <= 1e-6):
                exact = np.array_equal(values[left], values[right])
                reason = "duplicate_feature_vector" if exact else "near_duplicate_feature_vector"
                quarantined.setdefault(rows[right]["experiment_id"], []).append(
                    f"{reason}_with:{rows[left]['experiment_id']}"
                )
                near_pairs.append({
                    "left": rows[left]["experiment_id"],
                    "right": rows[right]["experiment_id"],
                    "kind": "exact" if exact else "near",
                    "relative_tolerance": 1e-6,
                })
    return quarantined, near_pairs


def _split_rows(frame: pd.DataFrame, seed: int) -> tuple[dict, str | None]:
    sessions = frame["_independent_session_key"].astype(str)
    if sessions.nunique() < 15:
        return {}, (
            "At least 15 independently verified IKE_SA session lifecycles are "
            "required to support the fixed 60/20/20 split with at least three "
            "sessions per split; UUIDs alone do not establish independence."
        )
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    train_validation_idx, test_idx = next(
        outer.split(frame, groups=sessions)
    )
    remaining = frame.iloc[train_validation_idx]
    relative_validation_size = 0.2 / 0.8
    inner = GroupShuffleSplit(
        n_splits=1, test_size=relative_validation_size, random_state=seed + 1
    )
    train_idx, validation_idx = next(
        inner.split(remaining, groups=sessions.iloc[train_validation_idx])
    )
    parts = {
        "train": remaining.iloc[train_idx],
        "validation": remaining.iloc[validation_idx],
        "test": frame.iloc[test_idx],
    }
    session_sets = {
        name: sorted(part["session_id"].astype(str).unique().tolist())
        for name, part in parts.items()
    }
    independent_session_sets = {
        name: sorted(part["_independent_session_key"].astype(str).unique().tolist())
        for name, part in parts.items()
    }
    if any(len(groups) < 3 for groups in session_sets.values()):
        return {}, (
            "The deterministic split assigned fewer than three independent sessions "
            f"to a split: { {name: len(groups) for name, groups in session_sets.items()} }. "
            "Collect more sessions; do not retry seeds until a favorable split appears."
        )
    if any(
        set(independent_session_sets[left]) & set(independent_session_sets[right])
        for left, right in (
            ("train", "validation"), ("train", "test"), ("validation", "test")
        )
    ):
        raise RuntimeError("Internal error: session leakage in generated split.")
    labels = set(frame["label"].astype(str))
    missing = {
        name: sorted(labels - set(part["label"].astype(str)))
        for name, part in parts.items()
    }
    if any(missing.values()):
        return {}, (
            "The deterministic session split does not represent every class in each "
            f"split: {missing}. Collect more independent sessions; do not retry seeds "
            "until a favorable split appears."
        )
    return {
        "strategy": "deterministic nested GroupShuffleSplit by verified IKE_SA lifecycle identity",
        "random_state": seed,
        "fractions": {"validation": 0.2, "test": 0.2},
        "session_ids": session_sets,
        "independent_session_keys": independent_session_sets,
        "experiment_ids": {
            name: sorted(part["experiment_id"].astype(str).tolist())
            for name, part in parts.items()
        },
        "row_counts": {name: int(len(part)) for name, part in parts.items()},
        "class_distributions": {
            name: part["label"].value_counts().sort_index().to_dict()
            for name, part in parts.items()
        },
        "overlap": {"train_validation": 0, "train_test": 0, "validation_test": 0},
    }, None


def prepare_dataset(manifest_path: Path, output_dir: Path, seed: int = 42) -> dict:
    manifest_path = manifest_path.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    structural_errors = validate_manifest_shape(manifest)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite dataset evidence: {output_dir}")

    feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    if feature_schema.get("schema_version") != manifest["feature_schema_version"]:
        raise ValueError("Manifest feature schema does not match the checked-in runtime contract.")
    feature_columns = [feature["name"] for feature in feature_schema["features"]]
    rows = []
    exclusions = []
    malformed: dict[int, list[str]] = {}
    for error in structural_errors:
        index_text, reason = error.split(":", 1)
        index = int(index_text.removeprefix("observations[").removesuffix("]"))
        malformed.setdefault(index, []).append(f"manifest_schema:{reason}")
    experiment_id_counts: dict[str, int] = {}
    for observation in manifest["observations"]:
        if isinstance(observation, dict) and isinstance(observation.get("experiment_id"), str):
            key = observation["experiment_id"]
            experiment_id_counts[key] = experiment_id_counts.get(key, 0) + 1
    for index, observation in enumerate(manifest["observations"]):
        if index in malformed or not isinstance(observation, dict):
            exclusions.append({
                "manifest_index": index,
                "experiment_id": observation.get("experiment_id")
                if isinstance(observation, dict) else None,
                "session_id": observation.get("session_id")
                if isinstance(observation, dict) else None,
                "reasons": sorted(set(malformed.get(index, ["manifest_schema:entry_not_object"]))),
            })
            continue
        if experiment_id_counts.get(observation["experiment_id"], 0) > 1:
            exclusions.append({
                "manifest_index": index,
                "experiment_id": observation["experiment_id"],
                "session_id": observation["session_id"],
                "reasons": ["duplicate_experiment_id"],
            })
            continue
        row, reasons = _observation_features(
            observation, manifest_path.parent, feature_columns,
            manifest["manifest_version"],
        )
        if row is not None and not reasons:
            rows.append(row)
        else:
            exclusions.append({
                "manifest_index": index,
                "experiment_id": observation.get("experiment_id"),
                "session_id": observation.get("session_id"),
                "reasons": sorted(set(reasons)),
            })

    duplicate_quarantine, duplicate_pairs = _duplicate_flags(rows, feature_columns) if rows else ({}, [])
    accepted = [
        row for row in rows if row["experiment_id"] not in duplicate_quarantine
    ]
    for row in rows:
        if row["experiment_id"] in duplicate_quarantine:
            exclusions.append({
                "experiment_id": row["experiment_id"],
                "session_id": row["session_id"],
                "reasons": sorted(set(duplicate_quarantine[row["experiment_id"]])),
            })

    frame = pd.DataFrame(accepted)
    if not frame.empty:
        frame = frame.sort_values(["session_id", "experiment_id"]).reset_index(drop=True)
    split_manifest, split_error = _split_rows(frame, seed) if not frame.empty else (
        {}, "No accepted observations remain after validation and quarantine."
    )
    status = "READY_FOR_REVIEW" if not split_error else "BLOCKED"

    output_dir.mkdir(parents=True, exist_ok=False)
    report = {
        "report_version": 1,
        "status": status,
        "dataset_id": manifest["dataset_id"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "manifest_schema": str(
            (MANIFEST_SCHEMA_V2_PATH if manifest["manifest_version"] == SCHEMA_VERSION_V2
             else MANIFEST_SCHEMA_PATH).relative_to(ROOT)
        ),
        "feature_schema_version": manifest["feature_schema_version"],
        "extractor_version": manifest["extractor_version"],
        "feature_columns": feature_columns,
        "source_observations": len(manifest["observations"]),
        "accepted_observations": len(accepted),
        "quarantined_observations": len(exclusions),
        "independent_session_count": (
            int(frame["_independent_session_key"].nunique()) if not frame.empty else 0
        ),
        "class_distribution": (
            frame["label"].value_counts().sort_index().to_dict() if not frame.empty else {}
        ),
        "missingness_by_feature": (
            frame[feature_columns].isna().sum().astype(int).to_dict()
            if not frame.empty else {name: 0 for name in feature_columns}
        ),
        "feature_ranges": {
            name: {
                "minimum": float(frame[name].min()),
                "maximum": float(frame[name].max()),
            }
            for name in feature_columns
        } if not frame.empty else {},
        "duplicate_and_near_duplicate_pairs": duplicate_pairs,
        "exclusions": exclusions,
        "split_manifest": split_manifest or None,
        "blocker": split_error,
        "feature_target_separation": {
            "target_column": "label",
            "metadata_columns_excluded_from_features": [
                "experiment_id", "session_id", "capture_path", "capture_sha256",
            ],
            "model_features": feature_columns,
        },
    }
    if status == "READY_FOR_REVIEW":
        output_path = output_dir / "prepared_dataset.csv"
        frame.drop(columns=["_independent_session_key"]).to_csv(output_path, index=False)
        report["prepared_dataset_path"] = output_path.name
        report["prepared_dataset_sha256"] = sha256_file(output_path)
        (output_dir / "split_manifest.json").write_text(
            json.dumps(split_manifest, indent=2) + "\n", encoding="utf-8"
        )
    (output_dir / "dataset_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate an experiment manifest and prepare a session-split dataset."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--random-state", type=int, default=42)
    args = parser.parse_args()
    result = prepare_dataset(args.manifest, args.output_dir, args.random_state)
    print(json.dumps({
        "status": result["status"],
        "accepted_observations": result["accepted_observations"],
        "quarantined_observations": result["quarantined_observations"],
        "sessions": result["independent_session_count"],
        "blocker": result["blocker"],
        "report": str(args.output_dir / "dataset_report.json"),
    }, indent=2))
    if result["status"] == "BLOCKED":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
