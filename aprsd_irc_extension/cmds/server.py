import datetime
import logging
import threading
import signal
import sys
import time

import click
from oslo_config import cfg


import aprsd
from aprsd import cli_helper, client, packets, stats
from aprsd import threads as aprsd_threads
from aprsd.threads import tx, registry, keep_alive

from aprsd_irc_extension.db import models
from aprsd_irc_extension.db import session as db_session
import aprsd_irc_extension
from aprsd_irc_extension import cmds, utils
from aprsd_irc_extension import conf  # noqa


CONF = cfg.CONF
LOG = logging.getLogger("APRSD")


def signal_handler(sig, frame):
    click.echo("signal_handler: called")
    aprsd_threads.APRSDThreadList().stop_all()
    if "subprocess" not in str(frame):
        LOG.info(
            "Ctrl+C, Sending all threads exit! Can take up to 10 seconds {}".format(
                datetime.datetime.now(),
            ),
        )
        time.sleep(1.5)
        packets.PacketTrack().save()
        packets.WatchList().save()
        packets.SeenList().save()
        LOG.info(stats.APRSDStats())
        # signal.signal(signal.SIGTERM, sys.exit(0))
        # sys.exit(0)


class InvalidChannelName(Exception):
    pass


class ChannelService:
    """Class for handling channel related commands."""

    @staticmethod
    def join(channel: str, user: str) -> models.Channel:
        """User wants to join a channel."""
        LOG.info(f"{user} has joined {channel}")
        session = db_session.get_session()
        user_obj = models.ChannelUsers(user=user)
        ch = models.Channel.find_by_name(session, channel)
        ch.users.append(user_obj)
        pkt = packets.MessagePacket(
            from_call=CONF.callsign,
            to_call=user,
            message_text=f"Welcome to channel {channel}",
        )
        tx.send(pkt)
        time.sleep(1)
        tx.send(packets.MessagePacket(
            from_call=CONF.callsign,
            to_call=user,
            message_text=f"Use /leave {channel} to leave",
        ))
        ch.save(session)
        session.remove()
        return channel

    @staticmethod
    def leave(channel: str, user: str) -> models.Channel:
        """User wants to leave a channel."""
        LOG.info(f"{user} wants to leave channel {channel}")
        session = db_session.get_session()
        ch = models.Channel.find_by_name(session, channel)
        LOG.info(repr(ch))
        found = False
        for user_obj in ch.users:
            if user_obj.user == user:
                found = True
                session.delete(user_obj)
                session.flush()
                session.commit()
                pkt = packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=user,
                    message_text=f"Left channel {channel}",
                )
                tx.send(pkt)

        if not found:
            LOG.warning(f"{user} not in channel {channel}")
            pkt = packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=user,
                message_text=f"not in channel {channel}",
            )
            tx.send(pkt)

        session.remove()
        return channel

    @staticmethod
    def add_message(channel: str, pkt: packets.MessagePacket) -> models.Channel:
        """Add a message to the channel."""
        LOG.info(f"Adding message to channel {channel}")
        session = db_session.get_session()
        ch = models.Channel.find_by_name(session, channel)
        ch.messages.append(models.ChannelMessages.new_message(pkt))
        ch.save(session)
        session.remove()
        return channel


class IRChannels:
    """List of IRC Channels."""
    _instance = None
    lock = threading.Lock()
    data: dict = {}
    db_session = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.data = {}
            cls._instance._load()
        return cls._instance

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def _load(self):
        LOG.info("IRChannels: Loading channels from DB")
        session = db_session.get_session()
        channels = session.query(models.Channel).all()
        for ch in channels:
            LOG.info(f"IRChannels: Loading channel {ch}")
            users = []
            for user in ch.users:
                users.append(user.user)
            LOG.info(f"IRChannels: Loading messages {len(ch.messages)}")
            self.data[ch.name] = users

        LOG.info(f"IRChannels: Loaded {len(self.data)} channels from DB")
        session.remove()

    def get(self, id):
        with self.lock:
            return self.data[id]

    def list(self, packet) -> None:
        """Send a list of channels and count of users in channel."""
        channels = models.Channel.get_all_channels()
        user = packet.from_call
        for ch in channels:
            pkt = packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=user,
                message_text=f"Channel {ch.name} Users({len(ch.users)})",
            )
            tx.send(pkt)

    def add_channel(self, name: str):
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        if name not in self.data:
            models.Channel.create_channel(name)
            # initialize w/o users
            self.data[name] = []

    def remove_channel(self, name: str) -> None:
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        if name in self.data:
            del self.data[name]

    def get_channel(self, name: str) -> models.Channel:
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        return self.data.get(name)

    def channel_exists(self, name: str) -> bool:
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        return name in self.data


class APRSDIRCProcessPacketThread(aprsd_threads.APRSDProcessPacketThread):
    # Commands for IRC Channels
    commands = {
        "/join": {"cmd": "join",
                  "desc": "/join #channel or /j #channel - Join a channel"},
        "/leave": {"cmd": "leave",
                   "desc": "/leave #channel or /l #channel - Leave a channel"},
    }
    short_commands = {
        "/j": {"cmd": "join",
               "desc": "/join #channel or /j #channel - Join a channel"},
        "/l": {"cmd": "leave",
               "desc": "/leave #channel or /l #channel - Leave a channel"},
    }

    server_commands = {
        "/list": {"cmd": "list",
                  "desc": "/list or /ls - list all channels"},
    }
    short_server_commands = {
        "/ls": {"cmd": "list",
                "desc": "/list or /ls - list all channels"},
    }

    def is_channel_command(self, message):
        msg_parts = message.split()
        for command in self.commands:
            if message.startswith(command):
                return True
        for command in self.short_commands:
            if msg_parts[0] == command:
                return True
        return False

    def get_channel_command(self, message):
        msg_parts = message.split()
        for command in self.commands:
            if message.startswith(command):
                return self.commands[command]
        for command in self.short_commands:
            if msg_parts[0] == command:
                return self.short_commands[command]
        return None

    def is_server_command(self, message):
        for command in self.server_commands:
            if message.startswith(command):
                return True
        for command in self.short_server_commands:
            if message.startswith(command):
                return True
        return False

    def get_server_command(self, message):
        for command in self.server_commands:
            if message.startswith(command):
                return self.server_commands[command]
        for command in self.short_server_commands:
            if message.startswith(command):
                return self.short_server_commands[command]
        return None

    def _user_channel_count(self, user):
        """How many channels is a user in?"""
        LOG.info(f"Checking how many channels {user} is in")
        LOG.info(f"IRChannels().data: {IRChannels().data}")
        count = 0
        found = {}
        session = db_session.get_session()
        for name in IRChannels():
            ch = models.Channel.find_by_name(session, name)
            LOG.info(f"Checking channel {ch.name} : {ch.users}")
            for user_ojb in ch.users:
                if user_ojb.user == user:
                    count += 1
                    found[ch.name] = ch.name
                    continue
        session.remove()

        LOG.info(f"User {user} is in {count} channels")
        return count, found

    def process_channel_command(self, packet, command_name, channel_name):
        fromcall = packet.from_call
        message = packet.get("message_text")
        ch = None
        if not channel_name:
            # They didn't specify a channel name
            # If this is leave
            # find how many channels the user is in
            if command_name == "/leave" or command_name == "/l":
                count, found = self._user_channel_count(fromcall)
                if count == 1:
                    channel_name = found.popitem()[1]
                else:
                    channel_names = ", ".join(found.keys())
                    LOG.info(f"User {fromcall} is in {count} channels ({channel_names}). "
                             "Need to specify channel when leaving.")
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text="Need to specify channel when leaving. /leave #channel",
                    ))
                    return

        session = None
        try:
            if IRChannels().channel_exists(channel_name):
                session = db_session.get_session()
                ch = models.Channel.find_by_name(session, channel_name)
        except InvalidChannelName as e:
            LOG.error(f"Failed to add channel: {e}")
            tx.send(packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=fromcall,
                message_text="Channel name must start with #",
            ))
            return
        finally:
            if session:
                session.remove()

        if not ch:
            ch = IRChannels().add_channel(channel_name)

        cmd_dict = self.get_channel_command(message)
        LOG.warning(f"cmd_dict: {cmd_dict}")
        if not cmd_dict:
            LOG.info(f"Unknown command: {command_name}")
            tx.send(
                packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=fromcall,
                    message_text=f"Unknown command: {command_name}",
                )
            )
            return

        svc = ChannelService
        cmd = getattr(svc, cmd_dict["cmd"])
        cmd(channel_name, fromcall)
        return

    def process_irc_command(self, packet):
        message = packet.get("message_text")
        msg_parts = message.split()
        command_name = msg_parts[0]
        try:
            channel_name = msg_parts[1]
        except IndexError:
            channel_name = None
        self.process_channel_command(packet, command_name, channel_name)

    def process_server_command(self, packet):
        fromcall = packet.from_call
        message = packet.get("message_text")
        msg_parts = message.split()
        command_name = msg_parts[0]
        cmd_dict = self.get_server_command(message)
        LOG.warning(f"cmd_dict: {cmd_dict}")
        if not cmd_dict:
            LOG.info(f"Unknown command: {command_name}")
            tx.send(
                packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=fromcall,
                    message_text=f"Unknown command: {command_name}",
                )
            )
            return
        cmd = getattr(IRChannels(), cmd_dict["cmd"])
        cmd(packet)
        return

    def process_our_message_packet(self, packet):
        irc_channels = IRChannels()
        fromcall = packet.from_call
        message = packet.get("message_text")

        # check to see if there are channel commands
        if self.is_channel_command(message):
            LOG.info(f"Processing channel command: {message}")
            self.process_irc_command(packet)
            return
        elif self.is_server_command(message):
            LOG.info(f"Processing server command: {message}")
            self.process_server_command(packet)
            return
        else:
            if message.startswith("help"):
                # They want a list of commands
                LOG.info(f"Send help message to {fromcall}")
                for command in self.commands:
                    cmd = self.commands.get(command)
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text=f"{cmd['desc']}",
                    ))
                for command in self.server_commands:
                    cmd = self.server_commands.get(command)
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text=f"{cmd['desc']}",
                    ))
                return

            # If not a channel command, then it's a message
            # to a channel or user
            channel_name = message.split()[0]
            LOG.info(f"Send message to channel {channel_name}??")
            ch = None
            session = db_session.get_session()
            try:
                ch = irc_channels.get_channel(channel_name)
            except InvalidChannelName as e:
                count, found = self._user_channel_count(fromcall)
                if count == 1:
                    channel_name = found.popitem()[1]
                    message = f"{channel_name} {message}"
                    ch = models.Channel.find_by_name(session, channel_name)
                elif count > 1:
                    LOG.info("Failed to get channel from a user message. User in more than 1 channel")
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text="Need to specify channel when sending a message. '#channel msg'",
                    ))
                    session.remove()
                    return
                elif count == 0:
                    LOG.error(f"User is not in any channels: {e}")
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text="Must join a channel to send a message. try /list",
                    ))
                    session.remove()
                    return
                else:
                    LOG.error(f"Failed to get channel: {e}")
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text="Channel name must start with #",
                    ))
                    session.remove()
                    return

            if ch:
                found = False
                for user_obj in ch.users:
                    if user_obj.user == fromcall:
                        found = True

                if not found:
                    LOG.error(f"{fromcall} not in channel {channel_name}")
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text=f"{fromcall} not in channel {channel_name}",
                    ))
                    tx.send(packets.MessagePacket(
                        from_call=CONF.callsign,
                        to_call=fromcall,
                        message_text=f"Send /join {channel_name} to join channel",
                    ))
                    session.remove()
                    return

                msg = message.replace(ch.name, f"{ch.name} {fromcall}")
                for user_obj in ch.users:
                    if user_obj.user != fromcall:
                        tx.send(packets.MessagePacket(
                            from_call=CONF.callsign,
                            to_call=user_obj.user,
                            message_text=msg,
                        ))
                session.remove()
                ChannelService.add_message(ch.name, packet)
            else:
                LOG.error(f"Channel {channel_name} not found")
                tx.send(packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=fromcall,
                    message_text=f"Channel {channel_name} not found",
                ))
                time.sleep(1)
                tx.send(packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=fromcall,
                    message_text=f"Use /join {channel_name} to create it",
                ))


class ChannelInfoThread(aprsd_threads.APRSDThread):
    _loop_cnt: int = 1

    def __init__(self):
        super().__init__("ChannelInfo")
        self._loop_cnt = 1

    def loop(self):
        # Only dump out the stats every 60 seconds
        if self._loop_cnt % 60 == 0:
            session = db_session.get_session()
            irc_channels = session.query(models.Channel).all()
            for ch in irc_channels:
                LOG.info(repr(ch))
        self._loop_cnt += 1
        time.sleep(1)
        return True


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
def server(ctx, flush):
    """Run an APRS IRC server."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    level, msg = utils._check_version()
    if level:
        LOG.warning(msg)
    else:
        LOG.info(msg)
    LOG.info(f"APRSD IRC Started version: {aprsd_irc_extension.__version__}")
    LOG.info(f"APRSD version: {aprsd.__version__}")

    # Initialize the client factory and create
    # The correct client object ready for use
    client.ClientFactory.setup()

    # Dump all the config options now.
    CONF.log_opt_values(LOG, logging.DEBUG)

    # Make sure we have 1 client transport enabled
    if not client.factory.is_client_enabled():
        LOG.error("No Clients are enabled in config.")
        sys.exit(-1)

    if not client.factory.is_client_configured():
        LOG.error("APRS client is not properly configured in config file.")
        sys.exit(-1)

    # Now load the msgTrack from disk if any
    packets.PacketList()
    if flush:
        LOG.debug("Deleting saved objects.")
        packets.PacketTrack().flush()
        packets.WatchList().flush()
        packets.SeenList().flush()
    else:
        # Try and load saved MsgTrack list
        LOG.debug("Loading saved objects.")
        packets.PacketTrack().load()
        packets.WatchList().load()
        packets.SeenList().load()

    # Make sure the #lounge channel exists
    IRChannels().add_channel("#lounge")

    keepalive = keep_alive.KeepAliveThread()
    keepalive.start()

    rx_thread = aprsd_threads.APRSDDupeRXThread(
        packet_queue=aprsd_threads.packet_queue,
    )
    process_thread = APRSDIRCProcessPacketThread(
        packet_queue=aprsd_threads.packet_queue,
    )
    channel_info_thread = ChannelInfoThread()

    if CONF.aprs_registry.enabled:
        LOG.info("Registry Enabled.  Starting Registry thread.")
        registry_thread = registry.APRSRegistryThread()
        registry_thread.start()

    if CONF.enable_beacon:
        LOG.info("Beacon Enabled.  Starting Beacon thread.")
        bcn_thread = tx.BeaconSendThread()
        bcn_thread.start()

    rx_thread.start()
    process_thread.start()
    channel_info_thread.start()
    packets.PacketTrack()

    rx_thread.join()
    keepalive.join()
