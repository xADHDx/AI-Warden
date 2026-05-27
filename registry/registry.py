import json
import os

REGISTRY_PATH = "/opt/aiwarden/registry/registry.json"

# Local ontology ID mappings - never transmitted, never published
# These are the only place where IDs map to real meanings
SERVICE_CLASSES = {
    1: "web_server",
    2: "database",
    3: "proxy",
    4: "media_server",
    5: "vpn",
    6: "monitoring",
    7: "game_server",
    8: "file_server",
    9: "mail_server",
    10: "dns_server"
}

KNOWN_ISSUES = {
    1: "authentication_failure",
    2: "network_timeout",
    3: "disk_full",
    4: "memory_exhaustion",
    5: "process_crash",
    6: "dependency_missing",
    7: "permission_denied",
    8: "config_error",
    9: "certificate_expired",
    10: "port_conflict",
    11: "codec_missing",
    12: "transcode_failure",
    13: "database_corruption",
    14: "backup_failure"
}

FIX_CLASSES = {
    1: "restart_service",
    2: "reinstall_dependency",
    3: "clear_cache",
    4: "rotate_credentials",
    5: "expand_storage",
    6: "update_config",
    7: "fix_permissions",
    8: "restore_snapshot",
    9: "rebuild_index",
    10: "flush_connections"
}

class ServiceRegistry:
    # Local service profile registry
    # Maps numeric ontology IDs to real meanings
    # Never transmitted, never published

    def __init__(self):
        self._registry = {}
        self._load_or_create()

    def _load_or_create(self):
        # Load existing registry or create default
        if os.path.exists(REGISTRY_PATH):
            with open(REGISTRY_PATH, "r") as f:
                self._registry = json.load(f)
        else:
            self._registry = {
                "services": {},
                "service_classes": SERVICE_CLASSES,
                "known_issues": KNOWN_ISSUES,
                "fix_classes": FIX_CLASSES
            }
            self._save()

    def get_channel_b(self, service_token):
        # Build anonymous Channel B payload using only numeric IDs
        # No human readable labels ever leave this method
        entry = self._registry["services"].get(str(service_token), {})
        return {
            "SC": entry.get("service_class_id", 0),
            "KI": entry.get("known_issue_id", 0),
            "FC": entry.get("fix_class_id", 0)
        }

    def register_service(self, token, service_class_id,
                        known_issue_id=0, fix_class_id=0):
        # Register a service token with its ontology IDs
        self._registry["services"][str(token)] = {
            "service_class_id": service_class_id,
            "known_issue_id": known_issue_id,
            "fix_class_id": fix_class_id
        }
        self._save()

    def resolve_fix(self, fix_class_id):
        # Translate a fix class ID back to a real action locally
        return FIX_CLASSES.get(fix_class_id, "unknown")

    def _save(self):
        # Persist registry to disk
        os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
        with open(REGISTRY_PATH, "w") as f:
            json.dump(self._registry, f, indent=2)