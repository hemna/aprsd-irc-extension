import logging

import click
from oslo_config import cfg
from rich.console import Console

from aprsd import cli_helper
from aprsd.conf import log as aprsd_conf_log

from aprsd_irc_extension.db import session as db_session
import aprsd_irc_extension
from aprsd_irc_extension import cmds
from aprsd_irc_extension import conf  # noqa
from aprsd_irc_extension.db import models


CONF = cfg.CONF
LOG = logging.getLogger("APRSD")


@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.option(
    "-f",
    "--flush",
    "flush",
    is_flag=True,
    show_default=True,
    default=False,
    help="Flush out all old aged messages on disk.",
)
@click.pass_context
@cli_helper.process_standard_options
def db(ctx, flush):
    """Initialize and upgrade the DB schema."""

    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")

    CONF.log_opt_values(
        LOG,
        aprsd_conf_log.LOG_LEVELS[CONF.logging.log_level]
    )

    engine = db_session.get_engine()
    db_session.init_db_schema(engine)


@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.option(
    "-f",
    "--flush",
    "flush",
    is_flag=True,
    show_default=True,
    default=False,
    help="Flush out all old aged messages on disk.",
)
@click.pass_context
@cli_helper.process_standard_options
def db_revision(ctx, flush):
    """Get the current revision of the DB schema."""

    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")

    CONF.log_opt_values(
        LOG,
        aprsd_conf_log.LOG_LEVELS[CONF.logging.log_level]
    )

    engine = db_session.get_engine()
    revision = db_session.get_revision(engine)
    LOG.info(f"DB schema revision: {revision}")


@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.option(
    "-f",
    "--flush",
    "flush",
    is_flag=True,
    show_default=True,
    default=False,
    help="Flush out all old aged messages on disk.",
)
@click.pass_context
@cli_helper.process_standard_options
def wipe_db(ctx, flush):
    """Completely wipe existing DB and Initialize and upgrade the DB schema."""

    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")

    CONF.log_opt_values(
        LOG,
        aprsd_conf_log.LOG_LEVELS[CONF.logging.log_level]
    )

    engine = db_session.get_engine()
    db_session.wipe_and_init_db_schema(engine)


@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.argument(
    "channel_name",
)
@click.pass_context
@cli_helper.process_standard_options
def delete_channel(ctx, channel_name):
    """Delete a channel from the DB."""
    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")
    if not channel_name.startswith("#"):
        channel_name = f"#{channel_name}"

    if click.confirm(f"Are you sure you want to delete Channel '{channel_name}'?"):
        LOG.info(f"Deleting Channel '{channel_name}'")
        try:
            models.Channel.delete_channel(channel_name)
        except Exception as ex:
            LOG.error(f"Error deleting Channel '{channel_name}': {ex}")

@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.argument("channel_name")
@click.pass_context
@cli_helper.process_standard_options
def create_channel(ctx, channel_name):
    """Create a channel in the DB."""
    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")
    if not channel_name.startswith("#"):
        channel_name = f"#{channel_name}"

    if click.confirm(f"Are you sure you want to create Channel '{channel_name}'?"):
        LOG.info(f"Creating Channel '{channel_name}'")
        try:
            models.Channel.create_channel(channel_name)
        except Exception as ex:
            LOG.error(f"Error creating Channel '{channel_name}': {ex}")

@cmds.irc.command()
@cli_helper.add_options(cli_helper.common_options)
@click.pass_context
@cli_helper.process_standard_options
def list_channels(ctx):
    """Delete a channel from the DB."""
    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")
    c = Console()

    channels = models.Channel.get_all_channels()
    for channel in channels:
        c.print(channel)
