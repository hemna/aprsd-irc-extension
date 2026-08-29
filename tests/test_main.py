"""Basic tests for aprsd_irc_extension package."""

import importlib.metadata

import pytest


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
