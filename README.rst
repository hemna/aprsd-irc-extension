========================================
APRSD extension add irc server via APRS!
========================================

WB4BOR
------

|pypi| |versions| |commit| |slack|


What is it?
===========
This is a pypi package for the `APRSD <https://github.com/craigerl/aprsd>`_ project that adds an IRC server
to `APRSD <https://github.com/craigerl/aprsd>`_

The IRC server has support for multiple channels and users.  This allows for
group based chats with APRS.  Users can create/join a channel and send messages to that channel.
Everyone else in the channel gets those messages and can reply.


Running APRS IRC Server as 'IRC'
================================
There is an existing running instance of the IRC server under the APRS network callsign of 'IRC'.
To connect to this server and join the default channel, send an APRS message to 'IRC' with the following
text in the message body:

::

 /join #lounge

This will join you to the default channel of #lounge.  You can then chat with others in that channel by
sending messages to the channel.

Using the IRC server
====================

First you must join an existing channel.  Every instance with this extension has a default
channel of #lounge.  You can join that channel by sending an APRS message to 'IRC' with the following
text in the message body:


Joining a channel
-----------------
::

 /join #lounge

After you join the channel, you can send messages to the channel by sending an APRS message to 'IRC' with the following
text in the message body:

You can join multiple channels by simply sending another join command with the channel name.


Sending a message to a channel
------------------------------
::

 #lounge Hello World!

Everyone that is in the channel #lounge will get your message sent to them.

If you are only in 1 channel, you don't have to preface your message with the channel name.  If you are in multiple
channels, you must preface your message with the channel name.

For example, if you are only in the #lounge channel, you can simply send the following message to 'IRC':

::

 Hello World!


Leaving a channel
-----------------

You can leave a channel by sending an APRS message to 'IRC' with the following
text in the message body:

::

 /leave #lounge

This will remove you from the #lounge channel.

If you are only in 1 channel you can simply send the following message to 'IRC':

::

 /leave

This will remove you from the channel you are currently in.


Getting a list of channels
--------------------------

You can get a list of channels by sending an APRS message to 'IRC' with the following
text in the message body:

::

 /list

This will return a list of channels that are currently active on the server and how many users are in each channel.


Installing
==========

To install the extension, you have to have an install of `APRSD <https://github.com/craigerl/aprsd>`_ already.
That is typically installed into a virtualenv.  You can then install this extension into the same virtualenv.

::

 pip install aprsd-irc-extension

Then you can add the following to your aprsd config file:

::

 [aprsd-irc-extension]
 enabled = True
 default_channel = #lounge


Running the IRC server
======================
Once you have installed the extension, you can start the server by running the following command:

::

 aprsd irc server --loglevel debug




.. badges

.. |pypi| image:: https://img.shields.io/pypi/v/aprsd-irc-extension.svg
   :target: https://pypi.python.org/pypi/aprsd-irc-extension

.. |versions| image:: https://img.shields.io/pypi/pyversions/aprsd-irc-extension.svg
   :target: https://pypi.python.org/pypi/aprsd-irc-extension

.. |slack| image:: https://img.shields.io/badge/slack-@hemna/aprsd-blue.svg?logo=slack
    :target: https://hemna.slack.com/app_redirect?channel=C01KQSCP5RP

.. |commit| image:: https://img.shields.io/github/last-commit/hemna/aprsd-irc-extension
