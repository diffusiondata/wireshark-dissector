
-- Proto package
-- This package sets some constants used in the Diffusion protocol.

-- Package header
local master = diffusion or {}
if master.const ~= nil then
    return master.const
end

-- Constants used by topic types
local topicTypes = {
    NONE = 0x00,
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
    TIME_SERIES = 0x10,
    STRING = 0x11,
    INT64 = 0x12,
    DOUBLE = 0x13,
    RECORD_V2 = 0x14,
    UNKNOWN = 0x15,
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
        [0x10] = "TIME_SERIES",
        [0x11] = "STRING",
        [0x12] = "INT64",
        [0x13] = "DOUBLE",
        [0x14] = "RECORD_V2",
        [0x15] = "UNKNOWN"
    }
}

-- Constants used by paged topic ordering
local ordering = {
    UNORDERED = 0x00,
    DECLARED = 0x01,
    COMPARATOR = 0x02,
    byByte = {
        [0x00] = "UNORDERED",
        [0x01] = "DECLARED",
        [0x02] = "COMPARATOR"
    }
}

-- Constants used by paged topic duplicates
local duplicates = {
    FIRST = 0x01,
    LAST = 0x02,
    NOT_ALLOWED = 0x03,
    byByte = {
        [0x01] = "FIRST",
        [0x02] = "LAST",
        [0x03] = "NOT_ALLOWED"
    }
}

-- Constants used by paged topic order
local order = {
    ASCENDING = 0x00,
    DESCENDING = 0x01,
    byByte = {
        [0x00] = "ASCENDING",
        [0x01] = "DESCENDING"
    }
}

-- Constants used by paged topic order
local ruleType = {
    NONE = 0x00,
    COLLATION = 0x01,
    byByte = {
        [0x00] = "NONE",
        [0x01] = "COLLATION"
    }
}

-- Constants used by topic properties
local topicProperty = {
    byByte = {
        [0x02] = "ATTACHMENT_CLASS",
        [0x03] = "DATA_INITIALISER_CLASS",
        [0x04] = "DELTA_ACK_REQUIRED",
        [0x05] = "DELTA_ENCODING",
        [0x08] = "DELTA_MESSAGE_CAPACITY",
        [0x0a] = "LOAD_ACK_REQUIRED",
        [0x0b] = "LOAD_ENCODING",
        [0x0e] = "LOAD_HEADERS",
        [0x0f] = "LOAD_MESSAGE_CAPACITY",
        [0x10] = "LOCK_TIMEOUT",
        [0x11] = "LOCKABLE",
        [0x12] = "SUBSCRIPTION_HANDLER_CLASS",
        [0x1e] = "PUBLISH_VALUES_ONLY",
        [0x1f] = "VALIDATE_VALUES",
    }
}

-- Package footer
master.const = {
    topicTypes = topicTypes,
    ordering = ordering,
    duplicates = duplicates,
    order = order,
    ruleType = ruleType,
    topicProperty = topicProperty
}
diffusion = master
return master.const
