#!/bin/sh
# Install the DPT wireshark dissector

# Clean up existing files and copy new ones
rm -f ~/.wireshark/dpt.*.lua && cp ./dpt.*.lua ~/.wireshark

# TODO: Find and update init.lua script

