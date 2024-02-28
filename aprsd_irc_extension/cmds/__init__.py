import click

from aprsd.cli_helper import AliasedGroup
from aprsd.main import cli


@cli.group(cls=AliasedGroup, aliases=['irc'], help="IRC related commands for APRSD")
@click.pass_context
def irc(ctx):
    pass
