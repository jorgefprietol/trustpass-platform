from trustpass.config import Settings


def test_env_config_reads_secret_files(settings, tmp_path, monkeypatch):
    api = tmp_path / "api"
    internal = tmp_path / "internal"
    api.write_text(settings.api_token)
    internal.write_text(settings.internal_token)
    monkeypatch.setenv("SERVICE_ROLE", "audit")
    monkeypatch.setenv("API_TOKEN_FILE", str(api))
    monkeypatch.setenv("INTERNAL_TOKEN_FILE", str(internal))
    result = Settings.from_env()
    assert result.role == "audit"
    assert result.api_token == settings.api_token
    monkeypatch.setenv("SERVICE_ROLE", "unsupported")
    import pytest

    with pytest.raises(ValueError, match="Unsupported"):
        Settings.from_env()
