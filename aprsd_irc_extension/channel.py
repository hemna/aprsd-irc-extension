"""Helpers for APRSD IRC channel commands."""


def channel_usage_message(command_name: str) -> str:
    """Return the usage message for a channel command without a name."""
    return f"Usage: {command_name} #channel"


def normalize_channel_name(name: str) -> str:
    """Normalize a user-supplied channel name to the IRC form."""
    return name if name.startswith("#") else f"#{name}"
