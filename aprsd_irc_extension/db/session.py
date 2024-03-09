import logging
from functools import lru_cache
#from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from oslo_config import cfg
from aprsd_irc_extension import conf  # noqa

CONF = cfg.CONF
LOG = logging.getLogger("APRSD")


@lru_cache
def create_session() -> scoped_session:
    LOG.info(f"Using DB URL {CONF.aprsd_irc_extension.db_dsn}")
    engine = create_engine(CONF.aprsd_irc_extension.db_dsn, pool_pre_ping=True)
    LOG.info(f"Engine {engine}")
    Session = scoped_session(
        sessionmaker(autoflush=True, bind=engine)
    )
    return Session


class MySession:
    _session = None
    _instance = None
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._session = create_session()
        return cls._instance

    @property
    def session(self):
        if not self._session:
            self._session = create_session()
        return self._session

    def close(self):
        self._session.remove()
        self._session = None


def get_session():
    ses = MySession().session
    LOG.debug(f"session {ses} {ses.info}")
    return ses


def close_session():
    MySession().close()
    LOG.debug("session closed")
