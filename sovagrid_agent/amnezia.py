# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Independent validation for the optional root-owned Amnezia control client."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex


HELPER = "/usr/local/bin/sovagrid-amnezia-ctl"
CLIENT = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
RECIPIENT = re.compile(r"[A-Za-z0-9_-]{87}\Z")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
ENVELOPE_FIELDS = {"version", "ephemeral_public_key", "salt", "nonce", "ciphertext"}
PROFILE_FORMATS = {"awg2": "awg3-conf", "wireguard": "wg-conf"}
PREVIEW_FIELDS = {"target", "container_id", "image_id", "config_sha256", "table_sha256",
                  "generation", "protocol", "interface", "listen_port", "server_address",
                  "server_subnet", "configured_clients", "managed_clients", "external_clients",
                  "awg_parameters", "awg_parameters_runtime_verified",
                  "header_protection_key_present", "awg3_required_parameters_present",
                  "apply_supported", "apply_blockers"}
AWG_NUMBERS = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"}
AWG_RANGES = {"H1", "H2", "H3", "H4"}
PREVIEW_BLOCKERS = ["CLIENT_PROFILES_REQUIRE_REISSUE",
                    "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"]
PLAN_FIELDS = {"target", "container_id", "image_id", "generation", "config_sha256",
               "table_sha256", "proposed_config_sha256", "current_awg_parameters",
               "proposed_awg_parameters", "changed_fields", "configured_clients",
               "apply_supported", "apply_blockers"}
INTENT_FIELDS = {"target", "action", "confirmation_id", "expires_at", "generation",
                 "config_sha256", "proposed_config_sha256", "changed_fields",
                 "configured_clients"}
APPLY_FIELDS = {"target", "action", "generation", "config_sha256",
                "cleanup_required"}


def _awg_patch(value: object, *, complete: bool = False,
               canonical: bool = True) -> bool:
    if (not isinstance(value, dict) or not value or
            set(value) - (AWG_NUMBERS | AWG_RANGES) or
            (complete and set(value) != AWG_NUMBERS | AWG_RANGES)):
        return False
    for name, item in value.items():
        if not isinstance(item, str) or not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", item):
            return False
        parts = [int(part) for part in item.split("-")]
        if ((canonical and item != "-".join(str(part) for part in parts)) or
                max(parts) > (65535 if name in AWG_NUMBERS else 4294967295) or
                (len(parts) == 2 and (name in AWG_NUMBERS or parts[0] > parts[1]))):
            return False
    return not ("Jmin" in value and "Jmax" in value and
                int(value["Jmin"]) > int(value["Jmax"]))


def _key(value: str) -> bool:
    if not RECIPIENT.fullmatch(value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, base64.binascii.Error):
        return False
    return (len(raw) == 65 and raw[0] == 4 and
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)


def _confirmation(value: object) -> bool:
    return _binary(value, 32, 32) if isinstance(value, str) and len(value) == 43 else False


def _host(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        return "." in value and all(DNS_LABEL.fullmatch(label) for label in value.split("."))


def command_argv(command: str) -> list[str] | None:
    if not isinstance(command, str) or HELPER not in command:
        return None
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError("Invalid Amnezia broker command") from exc
    if (len(argv) < 3 or argv[0] != HELPER or argv[2] not in PROFILE_FORMATS or
            shlex.join(argv) != command):
        raise ValueError("Invalid Amnezia broker command")
    action = argv[1]
    if action in ("status", "settings-preview") and len(argv) == 3:
        return argv
    if action in ("settings-plan", "settings-intent", "settings-apply") and argv[2] == "awg2" and len(argv) == (
            6 if action == "settings-plan" else 7 if action == "settings-intent" else 8):
        if (not re.fullmatch(r"[0-9a-f]{64}", argv[3]) or
                not re.fullmatch(r"(?:0|[1-9][0-9]{0,8}|1000000000)", argv[4])):
            raise ValueError("Invalid Amnezia settings proposal")
        patch_index = 5 if action == "settings-plan" else 6
        if action != "settings-plan" and (
                not re.fullmatch(r"[0-9a-f]{64}", argv[5]) or argv[5] == argv[3]):
            raise ValueError("Invalid Amnezia settings proposal")
        if action == "settings-apply" and not _confirmation(argv[7]):
            raise ValueError("Invalid Amnezia settings confirmation")
        try:
            patch = json.loads(argv[patch_index], object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid Amnezia settings proposal") from exc
        if (not _awg_patch(patch) or
                argv[patch_index] != json.dumps(patch, sort_keys=True, separators=(",", ":"))):
            raise ValueError("Invalid Amnezia settings proposal")
        return argv
    if action in ("revoke", "sealed-export", "add-profile"):
        if len(argv) < 4 or not CLIENT.fullmatch(argv[3]):
            raise ValueError("Invalid Amnezia client")
    if action == "revoke" and len(argv) == 4:
        return argv
    if action == "sealed-export" and len(argv) == 5 and _key(argv[4]):
        return argv
    if action == "add-profile" and len(argv) == 9 and argv[7] == "--route":
        try:
            address = ipaddress.IPv4Address(argv[4])
        except ipaddress.AddressValueError as exc:
            raise ValueError("Invalid Amnezia address") from exc
        if (str(address) == argv[4] and _host(argv[5]) and _key(argv[6]) and
                argv[8] in ("split", "full")):
            return argv
    raise ValueError("Invalid Amnezia broker command")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Amnezia result field")
        result[key] = value
    return result


def _binary(value, minimum: int, maximum: int, *, point: bool = False) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error):
        return False
    return (minimum <= len(raw) <= maximum and
            (not point or raw[0] == 4) and
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)


def _envelope(value: object) -> bool:
    return (isinstance(value, dict) and set(value) == ENVELOPE_FIELDS and
            type(value["version"]) is int and value["version"] == 1 and
            _binary(value["ephemeral_public_key"], 65, 65, point=True) and
            _binary(value["salt"], 16, 16) and _binary(value["nonce"], 12, 12) and
            _binary(value["ciphertext"], 17, 4096))


def _settings_preview(value: dict, target: str) -> bool:
    if set(value) != PREVIEW_FIELDS or value["target"] != target:
        return False
    for field in ("container_id", "config_sha256", "table_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            return False
    if not isinstance(value["image_id"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]):
        return False
    if (value["protocol"] != ("amneziawg" if target == "awg2" else "wireguard") or
            value["interface"] != ("awg0" if target == "awg2" else "wg0")):
        return False
    for field, maximum in (("generation", 1_000_000_000), ("listen_port", 65535),
                           ("configured_clients", 2048), ("managed_clients", 2048),
                           ("external_clients", 2048)):
        if type(value[field]) is not int or not 0 <= value[field] <= maximum:
            return False
    if (value["listen_port"] == 0 or value["managed_clients"] + value["external_clients"] !=
            value["configured_clients"]):
        return False
    try:
        address = ipaddress.IPv4Address(value["server_address"])
        network = ipaddress.IPv4Network(value["server_subnet"], strict=True)
    except (TypeError, ValueError):
        return False
    if (str(address) != value["server_address"] or str(network) != value["server_subnet"] or
            address not in network):
        return False
    for field in ("awg_parameters_runtime_verified", "header_protection_key_present",
                  "awg3_required_parameters_present", "apply_supported"):
        if type(value[field]) is not bool:
            return False
    if (value["awg_parameters_runtime_verified"] or value["apply_supported"] or
            value["apply_blockers"] != PREVIEW_BLOCKERS):
        return False
    parameters = value["awg_parameters"]
    if not isinstance(parameters, dict) or set(parameters) - (AWG_NUMBERS | AWG_RANGES):
        return False
    for name, number in parameters.items():
        if not isinstance(number, str) or not re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", number):
            return False
        parts = [int(part) for part in number.split("-")]
        if (max(parts) > (65535 if name in AWG_NUMBERS else 4294967295) or
                (len(parts) == 2 and (name in AWG_NUMBERS or parts[0] > parts[1]))):
            return False
    if "Jmin" in parameters and "Jmax" in parameters and int(parameters["Jmin"]) > int(parameters["Jmax"]):
        return False
    return ((not parameters and not value["header_protection_key_present"] and
             not value["awg3_required_parameters_present"]) if target == "wireguard" else
            value["awg3_required_parameters_present"] ==
            (AWG_NUMBERS | AWG_RANGES <= set(parameters) and value["header_protection_key_present"]))


def _settings_plan(value: dict, target: str) -> bool:
    if set(value) != PLAN_FIELDS or target != "awg2" or value["target"] != target:
        return False
    for field in ("container_id", "config_sha256", "table_sha256",
                  "proposed_config_sha256"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            return False
    if (not isinstance(value["image_id"], str) or
            not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"]) or
            value["config_sha256"] == value["proposed_config_sha256"] or
            type(value["generation"]) is not int or
            not 0 <= value["generation"] <= 1_000_000_000 or
            type(value["configured_clients"]) is not int or
            not 0 <= value["configured_clients"] <= 2048 or
            type(value["apply_supported"]) is not bool or
            not _awg_patch(value["current_awg_parameters"], complete=True,
                           canonical=False) or
            not _awg_patch(value["proposed_awg_parameters"], complete=True,
                           canonical=False)):
        return False
    current, proposed = value["current_awg_parameters"], value["proposed_awg_parameters"]
    changed = sorted(name for name in current if current[name] != proposed[name])
    blockers = ["CLIENT_PROFILES_REQUIRE_REISSUE"] if value["configured_clients"] else []
    return bool(changed and value["changed_fields"] == changed and
                value["apply_blockers"] == blockers and
                value["apply_supported"] is (value["configured_clients"] == 0))


def _settings_intent(value: dict, target: str) -> bool:
    if (target != "awg2" or set(value) != INTENT_FIELDS or
            value["target"] != target or value["action"] != "settings_intent" or
            not _confirmation(value["confirmation_id"]) or
            type(value["expires_at"]) is not int or
            not 0 < value["expires_at"] <= 253402300799 or
            type(value["generation"]) is not int or
            not 0 <= value["generation"] <= 1_000_000_000 or
            type(value["configured_clients"]) is not int or
            value["configured_clients"] != 0 or
            not isinstance(value["config_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", value["config_sha256"]) or
            not isinstance(value["proposed_config_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", value["proposed_config_sha256"]) or
            value["config_sha256"] == value["proposed_config_sha256"] or
            not isinstance(value["changed_fields"], list) or
            not value["changed_fields"] or len(value["changed_fields"]) > 11 or
            value["changed_fields"] != sorted(set(value["changed_fields"])) or
            any(name not in AWG_NUMBERS | AWG_RANGES for name in value["changed_fields"])):
        return False
    return True


def _settings_apply(value: dict, target: str) -> bool:
    return bool(target == "awg2" and set(value) == APPLY_FIELDS and
                value["target"] == target and value["action"] == "settings_updated" and
                type(value["generation"]) is int and
                1 <= value["generation"] <= 1_000_000_000 and
                isinstance(value["config_sha256"], str) and
                re.fullmatch(r"[0-9a-f]{64}", value["config_sha256"]) and
                type(value["cleanup_required"]) is bool)


def sanitize_result(action: str, output: str, expected_target: str,
                    expected_client: str | None = None) -> str | None:
    """Allow only broker-approved JSON fields into Hub jobs and SQLite."""
    if expected_target not in PROFILE_FORMATS:
        return None
    if action in ("settings-preview", "settings-plan", "settings-intent", "settings-apply") and (not isinstance(output, str) or
                                              len(output.encode("utf-8")) > 4096):
        return None
    try:
        value = json.loads(output, object_pairs_hook=_unique_pairs)
    except (TypeError, ValueError):
        return None
    if not isinstance(value, dict):
        return None
    if action == "sealed-export":
        if not _envelope(value):
            return None
    elif action == "settings-preview":
        if not _settings_preview(value, expected_target):
            return None
    elif action == "settings-plan":
        if not _settings_plan(value, expected_target):
            return None
    elif action == "settings-intent":
        if not _settings_intent(value, expected_target):
            return None
    elif action == "settings-apply":
        if not _settings_apply(value, expected_target):
            return None
    elif action == "status":
        if (set(value) != {"target", "enrolled", "recovery_required", "owned_clients"} or
                value["target"] != expected_target or type(value["enrolled"]) is not bool or
                type(value["recovery_required"]) is not bool or
                not isinstance(value["owned_clients"], list) or
                len(value["owned_clients"]) > 128 or
                any(not isinstance(name, str) or not CLIENT.fullmatch(name)
                    for name in value["owned_clients"]) or
                value["owned_clients"] != sorted(set(value["owned_clients"]))):
            return None
    elif action in ("add-profile", "revoke"):
        fields = {"target", "action", "client", "configured_clients", "cleanup_required"}
        if action == "add-profile":
            fields |= {"profile_format", "sealed_profile"}
        if (set(value) != fields or value["target"] != expected_target or
                value["action"] != ("added" if action == "add-profile" else "revoked") or
                not isinstance(value["client"], str) or
                not CLIENT.fullmatch(value["client"]) or
                (expected_client is not None and value["client"] != expected_client) or
                type(value["configured_clients"]) is not int or
                not 0 <= value["configured_clients"] <= 100000 or
                type(value["cleanup_required"]) is not bool):
            return None
        if action == "add-profile" and (value["profile_format"] != PROFILE_FORMATS[expected_target] or
                                         not _envelope(value["sealed_profile"])):
            return None
    else:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
