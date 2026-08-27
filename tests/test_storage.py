from session_assist.storage import Storage


def test_xdg_storage_keeps_recent_targets_and_permission(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    storage = Storage()
    storage.remember("host-one", "consent")
    storage.remember("HOST-ONE", "auto")
    settings = storage.load_settings()
    assert settings.recent == ["HOST-ONE"]
    assert settings.last_computer == "HOST-ONE"
    assert settings.assist_permission_mode == "auto"
    assert storage.settings_path.exists()
    assert storage.cache_dir == tmp_path / "cache" / "remote-control"


def test_favorites_are_case_insensitive_and_persist(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    storage = Storage()
    assert storage.add_favorite("Room-214") is True
    assert storage.add_favorite("room-214") is False
    assert storage.remove_favorite("ROOM-214") is True
    assert storage.load_settings().favorites == []


def test_favorite_friendly_name_is_persisted(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    storage = Storage()
    assert storage.add_favorite("Room-214", "Teacher workstation") is True
    settings = storage.load_settings()
    assert settings.favorite_names == {"Room-214": "Teacher workstation"}
