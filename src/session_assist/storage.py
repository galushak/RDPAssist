"""Per-user XDG configuration, state, and non-sensitive diagnostic logging."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _xdg(variable: str, fallback: str) -> Path:
    return Path(os.environ.get(variable, Path.home() / fallback)) / "remote-control"


@dataclass
class Settings:
    recent: list[str] = field(default_factory=list)
    favorites: list[str] = field(default_factory=list)
    last_computer: str = ""
    assist_permission_mode: str = "auto"
    max_recent_computers: int = 15
    rdp_dynamic_resolution: bool = True
    rdp_clipboard: bool = True
    rdp_audio: bool = True
    detailed_logging: bool = False
    ldap_server: str = ""
    ldap_search_base: str = ""
    favorite_names: dict[str, str] = field(default_factory=dict)


class Storage:
    def __init__(self) -> None:
        self.config_dir = _xdg("XDG_CONFIG_HOME", ".config")
        self.data_dir = _xdg("XDG_DATA_HOME", ".local/share")
        self.state_dir = _xdg("XDG_STATE_HOME", ".local/state")
        self.cache_dir = _xdg("XDG_CACHE_HOME", ".cache")
        self.log_dir = self.state_dir / "logs"
        self.settings_path = self.config_dir / "settings.json"

    def load_settings(self) -> Settings:
        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return Settings(
                recent=[str(item) for item in payload.get("recent", [])][:15],
                favorites=[str(item) for item in payload.get("favorites", [])],
                last_computer=str(payload.get("last_computer", "")),
                assist_permission_mode=str(payload.get("assist_permission_mode", "auto")),
                max_recent_computers=max(1, min(50, int(payload.get("max_recent_computers", 15)))),
                rdp_dynamic_resolution=bool(payload.get("rdp_dynamic_resolution", True)),
                rdp_clipboard=bool(payload.get("rdp_clipboard", True)),
                rdp_audio=bool(payload.get("rdp_audio", True)),
                detailed_logging=bool(payload.get("detailed_logging", False)),
                ldap_server=str(payload.get("ldap_server", "")),
                ldap_search_base=str(payload.get("ldap_search_base", "")),
                favorite_names={str(key): str(value) for key, value in dict(payload.get("favorite_names", {})).items()},
            )
        except (OSError, ValueError, TypeError):
            return Settings()

    def save_settings(self, settings: Settings) -> None:
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(settings), indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.settings_path)

    def remember(self, target: str, permission_mode: str | None = None) -> None:
        settings = self.load_settings()
        settings.recent = [target, *[item for item in settings.recent if item.lower() != target.lower()]][:settings.max_recent_computers]
        settings.last_computer = target
        if permission_mode:
            settings.assist_permission_mode = permission_mode
        self.save_settings(settings)

    def add_favorite(self, target: str, friendly_name: str = "") -> bool:
        settings = self.load_settings()
        match = next((item for item in settings.favorites if item.lower() == target.lower()), None)
        if match is None:
            settings.favorites.append(target)
            match = target
            changed = True
        else:
            changed = False
        if friendly_name and settings.favorite_names.get(match) != friendly_name:
            settings.favorite_names[match] = friendly_name
            changed = True
        settings.favorites.sort(key=str.lower)
        self.save_settings(settings)
        return changed

    def remove_favorite(self, target: str) -> bool:
        settings = self.load_settings()
        updated = [item for item in settings.favorites if item.lower() != target.lower()]
        if updated == settings.favorites:
            return False
        for key in list(settings.favorite_names):
            if key.lower() == target.lower():
                del settings.favorite_names[key]
        settings.favorites = updated
        self.save_settings(settings)
        return True

    def log(self, message: str, level: str = "INFO") -> None:
        self.log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.log_dir / f"remote-control-{datetime.now().date():%Y-%m-%d}.log"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{timestamp} [{level}] {message}\n")
