
-- Proto package
-- This package sets some constants used in the Diffusion protocol.

-- Package header
local master = diffusion or {}
if master.const ~= nil then
    return master.const
end

-- Constants used by topic types
local topicTypes = {
    NODE = 0x00,
    STATELESS = 0x01,
    DELEGATED = 0x02,
    SINGLE_VALUE = 0x03,
    RECORD = 0x04,
    PROTOCOL_BUFFER = 0x05,
    CUSTOM = 0x06,
    SLAVE = 0x07,
    SERVICE = 0x08,
    PAGED_STRING = 0x09,
    PAGED_RECORD = 0x0a,
    TOPIC_NOTIFY = 0x0b,
    ROUTING = 0x0c,
    CHILD_LIST = 0x0d,
    BINARY = 0x0e,
    JSON = 0x0f,
    byByte = {
        [0x00] = "NONE",
        [0x01] = "STATELESS",
        [0x02] = "DELEGATED",
        [0x03] = "SINGLE_VALUE",
        [0x04] = "RECORD",
        [0x05] = "PROTOCOL_BUFFER",
        [0x06] = "CUSTOM",
        [0x07] = "SLAVE",
        [0x08] = "SERVICE",
        [0x09] = "PAGED_STRING",
        [0x0a] = "PAGED_RECORD",
        [0x0b] = "TOPIC_NOTIFY",
        [0x0c] = "ROUTING",
        [0x0d] = "CHILD_LIST",
        [0x0e] = "BINARY",
        [0x0f] = "JSON",
    }
}

-- Package footer
master.const = {
    topicTypes = topicTypes
}
diffusion = master
return master.const
