from app.core.config import Settings

FAKE_KEY = "fake-test-key-not-a-real-credential"


def test_api_keys_are_masked_in_repr() -> None:
    settings = Settings(_env_file=None, virustotal_api_key=FAKE_KEY)

    assert FAKE_KEY not in repr(settings)
    assert FAKE_KEY not in str(settings.model_dump())
    assert settings.virustotal_api_key.get_secret_value() == FAKE_KEY


def test_api_keys_default_to_unset() -> None:
    settings = Settings(_env_file=None)

    assert settings.virustotal_api_key is None
    assert settings.abuseipdb_api_key is None
    assert settings.otx_api_key is None
