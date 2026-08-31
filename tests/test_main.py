"""Basic tests for aprsd_irc_extension package."""

import importlib.metadata

from aprsd_irc_extension.channel import (
    channel_usage_message,
    no_channel_membership_message,
    normalize_channel_name,
)
from aprsd_irc_extension.db.models import sanitize_message_text
from aprsd_irc_extension.statsstore import recover_statsstore


def test_sanitize_message_text_removes_nul_and_trailing_kiss_delimiters():
    assert sanitize_message_text("ack6056\u00c0\u00c0\x00raw frame") == "ack6056"


def test_sanitize_message_text_preserves_normal_message():
    assert sanitize_message_text("Hello world") == "Hello world"


def test_channel_usage_message_includes_channel_syntax():
    assert channel_usage_message("/join") == "Usage: /join #channel"


def test_user_without_channel_membership_gets_no_channel_message():
    assert no_channel_membership_message() == "Must join a channel to send a message. try /list"


def test_channel_name_without_hash_is_normalized():
    assert normalize_channel_name("lounge") == "#lounge"


def test_channel_name_with_hash_is_preserved():
    assert normalize_channel_name("#lounge") == "#lounge"


def test_recover_statsstore_moves_invalid_json(tmp_path):
    stats_path = tmp_path / "statsstore.json"
    stats_path.write_text('{"broken"')

    assert recover_statsstore(str(stats_path)) is True
    assert not stats_path.exists()
    assert (tmp_path / "statsstore.json.corrupt").read_text() == '{"broken"'


def test_recover_statsstore_ignores_valid_json(tmp_path):
    stats_path = tmp_path / "statsstore.json"
    stats_path.write_text('{}')

    assert recover_statsstore(str(stats_path)) is False
    assert stats_path.exists()


class TestVersion:
    """Tests for package version metadata."""

    def test_version_is_importable(self):
        """Package must be importable."""
        import aprsd_irc_extension  # noqa: F401

    def test_version_metadata(self):
        """Package must have version metadata when installed."""
        version = importlib.metadata.version("aprsd-irc-extension")
        assert isinstance(version, str)
        assert len(version) > 0

    def test_version_not_unknown(self):
        """Version must be set (not the sentinel 'unknown')."""
        version = importlib.metadata.version("aprsd-irc-extension")
        assert version != "unknown"


class TestEntryPoints:
    """Tests for registered entry points."""

    def test_aprsd_extension_entry_point_registered(self):
        """The aprsd.extension entry point must be registered."""
        eps = importlib.metadata.entry_points(group="aprsd.extension")
        names = [ep.name for ep in eps]
        assert "irc" in names

    def test_oslo_config_opts_entry_point_registered(self):
        """The oslo.config.opts entry point must be registered."""
        eps = importlib.metadata.entry_points(group="oslo.config.opts")
        names = [ep.name for ep in eps]
        assert "aprsd_irc_extension.conf" in names
