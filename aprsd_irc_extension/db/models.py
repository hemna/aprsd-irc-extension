import datetime
import logging
from typing import List

import sqlalchemy as sa
from sqlalchemy.orm import registry, relationship
from sqlalchemy.orm.decl_api import DeclarativeMeta
from sqlalchemy.sql.schema import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped
import sqlalchemy.ext.declarative as dec

import aprslib
from aprsd_irc_extension.db import session as db_session
from aprsd.packets import core as aprsd_packets

mapper_registry = registry()
ModelBase = dec.declarative_base()

LOG = logging.getLogger("APRSD")


class Base(metaclass=DeclarativeMeta):
    __abstract__ = True

    registry = mapper_registry
    metadata = mapper_registry.metadata

    __init__ = mapper_registry.constructor


class Channel(Base):
    __tablename__ = "channels"
    __allow_unmapped__ = True

    id = sa.Column(sa.Integer, sa.Sequence('channel_id_seq'), primary_key=True)
    name = sa.Column(sa.Text, nullable=False)
    messages: Mapped[List["ChannelMessages"]] = relationship(
        order_by="desc(ChannelMessages.timestamp)",
        back_populates="channel",
        lazy="dynamic"
    )  # type: ignore
    users: Mapped[List["ChannelUsers"]] = relationship(
        order_by="desc(ChannelUsers.user)",
        back_populates="channel",
        cascade="all, delete"
    )  # type: ignore

    def __repr__(self):
        users = [u.user for u in self.users]
        return (f"<Channel(name='{self.name}', users({len(self.users)})='{users}'), "
                f"messages({len(self.messages.all())})>")

    def to_json(self, include_messages=True):
        our_json = {
            "name": self.name,
            "users": [u.user for u in self.users],
            # "messages": [m.message for m in self.messages]
        }
        if include_messages:
            our_json["messages"] = [m.packet.to_json() for m in self.messages]

        return our_json

    @staticmethod
    def find_by_name(session, name: str) -> "Channel":
        try:
            channel = session.query(
                Channel
            ).filter(
                Channel.name == name
            ).one()
            return channel
        except sa.orm.exc.NoResultFound:
            return None

    @staticmethod
    def create_channel(name: str) -> "Channel":
        session = db_session.get_session()
        channel = Channel(name=name)
        session.add(channel)
        session.commit()
        return channel

    @staticmethod
    def get_all_channels() -> List["Channel"]:
        session = db_session.get_session()
        channels = session.query(Channel).all()
        return channels

    def save(self, session) -> None:
        LOG.debug(f"Saving {self} to DB")
        session.add(self)
        session.commit()

    @staticmethod
    def delete_channel(name: str) -> None:
        session = db_session.get_session()
        channel = Channel.find_by_name(session, name)
        if channel:
            session.delete(channel)
            session.commit()
        else:
            LOG.warning(f"Channel '{name}' not found")


class ChannelUsers(Base):
    __tablename__ = "channel_users"
    __allow_unmapped__ = True
    # A user can only be in the channel once
    __table_args__ = (UniqueConstraint("user", "channel_id", name="chan_users"),)

    id = sa.Column(sa.Integer, sa.Sequence('users_id_seq'), primary_key=True)
    user = sa.Column(sa.Text, nullable=False)
    channel_id = sa.Column(ForeignKey("channels.id"), nullable=False)
    channel: Mapped[Channel] = relationship(back_populates="users")

    @staticmethod
    def new_user(user: str) -> "ChannelUsers":
        obj = ChannelUsers(user=user)
        return obj

    @staticmethod
    def find_by_name(name: str) -> "ChannelUsers":
        session = db_session.get_session()
        try:
            user = session.query(
                ChannelUsers
            ).filter(
                ChannelUsers.user == name
            ).all()
            return user
        except sa.orm.exc.NoResultFound:
            return None

    def remove_from_channel(self) -> None:
        """Remove move the ChannelUser from it's channel."""
        session = db_session.get_session()
        session.delete(self)
        session.commit()


    def __repr__(self):
        return f"<ChannelUser(user='{self.user}', channel='{self.channel}')>"


class ChannelMessages(Base):
    __tablename__ = "channel_messages"
    __allow_unmapped__ = True

    id = sa.Column(sa.Integer, sa.Sequence('message_id_seq'), primary_key=True)
    channel_id = sa.Column(ForeignKey("channels.id"), nullable=False)
    channel: Mapped[Channel] = relationship(back_populates="messages")
    message = sa.Column(sa.Text, nullable=False)
    timestamp = sa.Column(sa.DateTime, server_default=sa.func.now(), nullable=False)

    def __repr__(self):
        return (f"<ChannelMessages(channel='{self.channel.name}', message='{self.message}', "
                f"time='{self.timestamp}')>")

    @staticmethod
    def new_message(packet: aprsd_packets.Packet) -> "ChannelMessages":
        obj = ChannelMessages(message=packet.raw)
        return obj

    @property
    def packet(self):
        pkt = aprsd_packets.factory(aprslib.parse(self.message))
        pkt.timestamp = self.timestamp
        return pkt


class UserSeen(Base):
    __tablename__ = "user_seen"
    __allow_unmapped__ = True

    id = sa.Column(sa.Integer, sa.Sequence('user_seen_id_seq'), primary_key=True)
    callsign = sa.Column(sa.Text, nullable=False)
    last = sa.Column(sa.DateTime, nullable=True)


    @staticmethod
    def find_by_callsign(callsign: str) -> "UserSeen":
        session = db_session.get_session()
        try:
            user = session.query(
                UserSeen
            ).filter(
                UserSeen.callsign == callsign
            ).one()
            return user
        except sa.orm.exc.NoResultFound:
            return None

    @staticmethod
    def delete_user(callsign: str) -> None:
        session = db_session.get_session()
        user = UserSeen.find_by_callsign(session, callsign)
        if user:
            session.delete(user)
            session.commit()
        else:
            LOG.warning(f"User '{callsign}' not found")

    @staticmethod
    def update_seen(callsign: str) -> None:
        session = db_session.get_session()
        user = UserSeen.find_by_callsign(callsign)
        if user:
            LOG.warning(f"Updating last seen for {callsign} last {user.last}")
            # user.last = sa.func.now()
            user.last = datetime.datetime.now()
        else:
            user = UserSeen(callsign=callsign, last=sa.func.now())
        session.add(user)
        session.commit()
