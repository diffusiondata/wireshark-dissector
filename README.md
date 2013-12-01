wireshark-dissector
===================

A Wireshark dissector for the DPT protocol, written in Lua. Exists to dissect the DPT protocol used by Diffusion
(http://www.pushtechnology.com)


Installation
============

+ Ensure your Wireshark has Lua installed
+ Minimum version of Wireshark?
+ Copy dpt.lua into ~/.wireshark
+ edit init.lua to include dofile(USER_DIR.."dpt.lua")

Displayed Information
=====================

The connection request and response from a handshake, after the handshake messages are exchanged messages are sent in
both directions. The connection request displays the protocol version, connection type and client capabilities. The
connection response displays the protocol version, connection response and client ID. If the connection is captured
from the beginning then this information will also be be displayed with each message. It will also explicitly state the
direction of the message. If the connection is not captured from the beginning then it is made clear that it is a
partial capture.

For each message the size, message type and encoding are displayed. If the message is unencoded then the content of the
message can be displayed. The content is divided into headers and the body. The fixed headers sent with each message
vary depending on the type. For messages sent over topics, the topic name should be extracted and if a it was sent as
an alias then the alias will be resolved to the topic name. Command messages are also displayed with the topic type,
topic category, the command, notification type and any parameters. Any user headers will be displayed as field
delimited values. The body of the message is separated into records and each record is separated into fields.

Filters
=======

It is possible to use Wireshark filters with fields provided by the DPT dissector. There are many fields that can be
used to filter on, here are a selection of useful fields.

| Filter field | Detail | Example |
| ------------ | ------ | ------- |
| dpt.message.type | Filter by the message type | dpt.message.type == 0x15 |
| dpt.message.encoding | Filter by the message encoding byte | dpt.message.type == 0x02 |
| dpt.header.topic | Filter by the topic name | dpt.header.topic == "Diffusion/Metrics/server/clients" |
| dpt.header.alias | Filter by the topic alias | dpt.header.topic == "!2" |
| dpt.header.command | Filter by the command message command | dpt.header.command == "O" |
| dpt.header.command.topicType | Filter by the command message topic type | dpt.header.command.topicType == "1" |
| dpt.header.command.topicCategory | Filter by the command message topic category | dpt.header.command.topicCategory == "PR" |
| dpt.header.command.notificationType | Filter by the command message notification type | dpt.header.command.notificationType == "P" |
| dpt.connection.protocolVersion | Filter connection requests by the protocol version byte | dpt.connection.protocolVersion == 4 |
| dpt.connection.connectionType | Filter connection requests by the connection type | dpt.connection.connectionType == 0x17 |
| dpt.connection.capabilities | Filter connection requests by the capabilities byte | dpt.connection.capabilities == 0x07 |
| dpt.connection.responseCode | Filter connection responses by the response code | dpt.connection.responseCode == 100 |

