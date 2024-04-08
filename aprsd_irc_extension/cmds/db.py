import logging

import click
from oslo_config import cfg

from aprsd import cli_helper
from aprsd.conf import log as aprsd_conf_log

from aprsd_irc_extension.db import session as db_session
import aprsd_irc_extension
from aprsd_irc_extension import cmds
from aprsd_irc_extension import conf  # noqa


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
def wipe_db(ctx, flush):
    """Completely wipe existing DB and Initialize and upgrade the DB schema."""

    LOG.info(f"aprsd-irc-extension version: {aprsd_irc_extension.__version__}")

    CONF.log_opt_values(
        LOG,
        aprsd_conf_log.LOG_LEVELS[CONF.logging.log_level]
    )

    engine = db_session.get_engine()
    db_session.wipe_and_init_db_schema(engine)
