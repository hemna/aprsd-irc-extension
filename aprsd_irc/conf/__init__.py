from oslo_config import cfg

from aprsd_irc.conf import main


CONF = cfg.CONF
main.register_opts(CONF)
