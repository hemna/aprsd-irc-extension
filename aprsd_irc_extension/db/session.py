import logging
import os
from functools import lru_cache
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from oslo_config import cfg
from aprsd_irc_extension import conf  # noqa
import aprsd_irc_extension

CONF = cfg.CONF
LOG = logging.getLogger("APRSD")


@lru_cache
def get_engine():
    LOG.info(f"Using DB URL {CONF.aprsd_irc_extension.db_dsn}")
    engine = create_engine(CONF.aprsd_irc_extension.db_dsn, pool_pre_ping=True)
    return engine


@lru_cache
def create_session() -> scoped_session:
    engine = get_engine()
    LOG.info(f"Engine {engine}")
    session = scoped_session(
        sessionmaker(autoflush=True, bind=engine)
    )
    return session


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
    return MySession().session


def close_session():
    MySession().close()
    LOG.debug("session closed")


def init_db_schema(engine):
    from aprsd_irc_extension.db import models
    models.Base.metadata.create_all(engine)
    LOG.info("DB schema initialized")

def get_revision(engine):
    from alembic.migration import MigrationContext
    context = MigrationContext.configure(engine.connect())
    return context.get_current_revision()

def revision_check(engine):
    from alembic.config import Config
    from alembic import command
    ini_path = os.path.dirname(aprsd_irc_extension.__file__) + "/alembic.ini"
    LOG.info(f"Using alembic.ini {ini_path}")
    alembic_cfg = Config(ini_path)
    try:
        result = command.check(alembic_cfg)
    except Exception as e:
        LOG.error(f"DB schema check failed {e}")
        return
    LOG.info(f"DB schema check {result}")

def upgrade_db_schema(engine):
    from alembic.config import Config
    from alembic import command
    ini_path = os.path.dirname(aprsd_irc_extension.__file__) + "/alembic.ini"
    LOG.info(f"Using alembic.ini {ini_path}")
    alembic_cfg = Config(ini_path)
    command.upgrade(alembic_cfg, "head")
    LOG.info("DB schema upgraded")

def generate_revision(engine):
    from alembic.config import Config
    from alembic import command
    ini_path = os.path.dirname(aprsd_irc_extension.__file__) + "/alembic.ini"
    LOG.info(f"Using alembic.ini {ini_path}")
    alembic_cfg = Config(ini_path)
    result = command.revision(alembic_cfg, autogenerate=True)
    LOG.info(f"Generated revision {result}")


def wipe_and_init_db_schema(engine):
    from aprsd_irc_extension.db import models
    models.Base.metadata.drop_all(engine)
    models.Base.metadata.create_all(engine)
    LOG.info("DB schema initialized")
