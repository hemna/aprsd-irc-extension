"""Helpers for APRSD IRC channel commands."""


def channel_usage_message(command_name: str) -> str:
    """Return the usage message for a channel command without a name."""
    return f"Usage: {command_name} #channel"


def no_channel_membership_message() -> str:
    """Return the response for a user without channel memberships."""
    return "Must join a channel to send a message. try /list"


def normalize_channel_name(name: str) -> str:
    """Normalize a user-supplied channel name to the IRC form."""
    return name if name.startswith("#") else f"#{name}"
