from oslo_config import cfg


irc_group = cfg.OptGroup(
    name="aprsd_irc_extension",
    title="APRSD IRC Extension settings",
)

irc_opts = [
    cfg.BoolOpt(
        "enabled",
        default=False,
        help="Enable the plugin?",
    ),
    cfg.StrOpt(
        "default_channel",
        default="#lounge",
        help="This default channel will always exist.",
    ),
    cfg.StrOpt(
        "db_dsn",
        default="sqlite:////tmp/aprsd-irc.db",
        help="The DSN URI for the database",
    ),
    cfg.IntOpt(
        "user_last_seen_max_age",
        # 86400 = 24 hours
        default=86400,
        help="The max age of a user last seen record in seconds. User will be removed after this time.",
    )
]

ALL_OPTS = irc_opts


def register_opts(cfg):
    cfg.register_group(irc_group)
    cfg.register_opts(ALL_OPTS, group=irc_group)


def list_opts():
    return {
        irc_group.name: irc_opts,
    }
