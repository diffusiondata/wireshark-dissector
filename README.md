wireshark-dissector
===================

A Wireshark dissector for the DPT protocol, written in Lua. Exists to dissect the DPT protocol used by Diffusion (http://www.pushtechnology.com)


Installation
============

. Ensure your Wireshark has Lua installed
. Minimum version of Wireshark?
. Copy dpt.lua into ~/.wireshark
. edit init.lua to include dofile(USER_DIR.."dpt.lua")