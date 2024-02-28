import datetime
import logging
import threading
import signal
import sys
import time

import click
from oslo_config import cfg

import aprsd
import aprsd_irc_extension
from aprsd_irc_extension import cmds, utils
from aprsd import cli_helper, client, packets, stats
from aprsd import threads as aprsd_threads
from aprsd.threads import tx
from aprsd.utils import objectstore


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
        IRChannels().save()
        LOG.info(stats.APRSDStats())
        # signal.signal(signal.SIGTERM, sys.exit(0))
        # sys.exit(0)


class InvalidChannelName(Exception):
    pass


class IRCChannel:
    """Base class for an IRC Channel."""

    def __init__(self, name):
        self.name = name
        self.users = set()
        self.messages = []

    def join(self, user):
        self.users.add(user)
        LOG.info(f"{user} has joined {self.name}")
        pkt = packets.MessagePacket(
            from_call=CONF.callsign,
            to_call=user,
            message_text=f"Welcome to channel {self.name}",
        )
        tx.send(pkt)
        time.sleep(1)
        tx.send(packets.MessagePacket(
            from_call=CONF.callsign,
            to_call=user,
            message_text=f"Use /leave {self.name} to leave",
        ))

    def leave(self, user):
        if user in self.users:
            self.users.remove(user)
            LOG.info(f"{user} has left {self.name}")
            pkt = packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=user,
                message_text=f"Left channel {self.name}",
            )
            tx.send(pkt)
        else:
            LOG.warning(f"{user} not in channel {self.name}")
            pkt = packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=user,
                message_text=f"not in channel {self.name}",
            )
            tx.send(pkt)

    def list(self, user):
        IRChannels().list(user)


class IRChannels(objectstore.ObjectStoreMixin):
    """List of IRC Channels."""
    _instance = None
    lock = threading.Lock()
    data: dict = {}

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_store()
            cls._instance.data = {}
        return cls._instance

    def list(self, packet):
        user = packet.from_call
        for channel_name in self.data:
            ch = self.get_channel(channel_name)
            pkt = packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=user,
                message_text=f"Channel {ch.name} Users({len(ch.users)})",
            )
            tx.send(pkt)

    def add_channel(self, name):
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        if name not in self.data:
            self.data[name] = IRCChannel(name)
        return self.data.get(name)

    def remove_channel(self, name):
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        if name in self.data:
            del self.data[name]

    def get_channel(self, name):
        if not name.startswith("#"):
            raise InvalidChannelName(
                "Channel name must start with #")
        return self.data.get(name)


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

    def process_channel_command(self, packet, command_name, channel_name):
        fromcall = packet.from_call
        message = packet.get("message_text")
        ch = None
        try:
            ch = IRChannels().get_channel(channel_name)
        except InvalidChannelName as e:
            LOG.error(f"Failed to add channel: {e}")
            tx.send(packets.MessagePacket(
                from_call=CONF.callsign,
                to_call=fromcall,
                message_text="Channel name must start with #",
            ))
            return

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
        cmd = getattr(ch, cmd_dict["cmd"])
        cmd(fromcall)
        return

    def process_irc_command(self, packet):
        message = packet.get("message_text")
        msg_parts = message.split()
        command_name = msg_parts[0]
        channel_name = msg_parts[1]
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
            LOG.info(f"Send message to channel {channel_name}")
            try:
                ch = irc_channels.get_channel(channel_name)
            except InvalidChannelName as e:
                LOG.error(f"Failed to get channel: {e}")
                tx.send(packets.MessagePacket(
                    from_call=CONF.callsign,
                    to_call=fromcall,
                    message_text="Channel name must start with #",
                ))
                return
            if ch:
                if fromcall not in ch.users:
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

                    return

                msg = message.replace(ch.name, f"{ch.name} {fromcall}")
                for user in ch.users:
                    if user != fromcall:
                        tx.send(packets.MessagePacket(
                            from_call=CONF.callsign,
                            to_call=user,
                            message_text=msg,
                        ))
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
            irc_channels = IRChannels()
            for ch in irc_channels:
                ch = irc_channels.get(ch)
                LOG.info(f"Channel: {ch.name} Users({len(ch.users)}): {ch.users}")
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
        IRChannels().flush()
    else:
        # Try and load saved MsgTrack list
        LOG.debug("Loading saved objects.")
        packets.PacketTrack().load()
        packets.WatchList().load()
        packets.SeenList().load()
        IRChannels().load()

    # Make sure the #lounge channel exists
    IRChannels().add_channel("#lounge")

    keepalive = aprsd_threads.KeepAliveThread()
    keepalive.start()

    rx_thread = aprsd_threads.APRSDDupeRXThread(
        packet_queue=aprsd_threads.packet_queue,
    )
    process_thread = APRSDIRCProcessPacketThread(
        packet_queue=aprsd_threads.packet_queue,
    )
    channel_info_thread = ChannelInfoThread()

    if CONF.enable_beacon:
        LOG.info("Beacon Enabled.  Starting Beacon thread.")
        bcn_thread = tx.BeaconSendThread()
        bcn_thread.start()

    rx_thread.start()
    process_thread.start()
    channel_info_thread.start()
    packets.PacketTrack().restart()

    rx_thread.join()
    keepalive.join()
