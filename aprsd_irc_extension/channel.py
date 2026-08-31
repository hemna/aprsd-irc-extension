"""Helpers for APRSD IRC channel commands."""


def channel_usage_message(command_name: str) -> str:
    """Return the usage message for a channel command without a name."""
    return f"Usage: {command_name} #channel"
