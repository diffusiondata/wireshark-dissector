
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

-- Constants used by topic properties, protocols 5-11
local olderTopicProperty = {
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

-- Constants used by topic properties, protocols 12+
local topicProperty = {
    byByte = {
        [0x02] = "TIME_SERIES_EVENT_VALUE_TYPE",
        [0x03] = "TIME_SERIES_RETAINED_RANGE",
        [0x04] = "TIME_SERIES_SUBSCRIPTION_RANGE",
        [0x05] = "SCHEMA",
        [0x06] = "DONT_RETAIN_VALUE",
        [0x07] = "PERSISTENT",
        [0x08] = "REMOVAL",
        [0x09] = "_CREATOR",
        [0x0a] = "CONFLATION",
        [0x0b] = "OWNER",
        [0x1e] = "PUBLISH_VALUES_ONLY",
        [0x1f] = "VALIDATE_VALUES"
    }
}

local responseCodes = {
    [100] = "OK - Connection Successful",
    [101] = "Invalid Connection Protocol",
    [103] = "One or more of the specified topics are invalid",
    [105] = "Reconnection Successful",
    [110] = "Topic already exists",
    [111] = "Connection Rejected",
    [112] = "Connection type not supported by connector",
    [113] = "Connection rejected due to license limit",
    [114] = "Reconnection not supported by connector",
    [115] = "Connection failed - protocol error",
    [116] = "Authentication failed",
    [117] = "Reconnection failed - the session is unknown",
    [127] = "Undefined error"
}

local capabilities = {
    [0x00] = "None",
    [0x01] = "Supports encrypted data messages",
    [0x02] = "Supports compressed data messages",
    [0x03] = "Supports encrypted and compressed data messages",
    [0x04] = "Supports base 64 encoded data messages",
    [0x05] = "Supports encrypted and base 64 encoded data messages",
    [0x06] = "Supports compressed and base 64 encoded data messages",
    [0x07] = "Supports encrypted, compressed and base 64 encoded data messages",
    [0x08] = "Is a Unified API client",
    [0x09] = "Supports encrypted data messages and is a Unified API client",
    [0x0a] = "Supports compressed data messages and is a Unified API client",
    [0x0b] = "Supports encrypted, compressed data messages and is a Unified API client",
    [0x0c] = "Supports base 64 encoded message and is a Unified API client",
    [0x0d] = "Supports encrypted, base 64 encoded data messages and is a Unified API client",
    [0x0e] = "Supports compressed, base 64 encoded data messages and is a Unified API client",
    [0x0f] = "Supports encrypted, compressed, base 64 encoded data messages and is a Unified API client"
}

local encodingTypesByValue = {
    [0] = "None",
    [1] = "Encryption requested",
    [2] = "Compression requested",
    [3] = "Base64 encoding requested",
    [0x11] = "Encrypted",
    [0x12] = "Compressed",
    [0x13] = "Base64 encoded"
}

local clientTypesByValue = {
    [0x01] = "Event Publisher",
    [0x02] = "UDP Event Publisher",
    [0x10] = "Publisher Client",
    [0x14] = "Unspecified Client",
    [0x15] = "Java Client",
    [0x16] = ".Net Client",
    [0x17] = "Flash Bridge Client",
    [0x18] = "Silverlight Bridge Client",
    [0x19] = "iPhone Client",
    [0x1a] = "J2ME Client",
    [0x1b] = "Android Client",
    [0x1c] = "Blackberry Client",
    [0x1d] = "C Client",
    [0x1e] = "Perl Client",
    [0x1f] = "Introspector Client",
    [0x20] = "Windows Phone Client",
    [0x21] = "iPad Client",
    [0x22] = "Flash Client",
    [0x23] = "Silverlight Client",
    [0x28] = "UDP Java Client",
    [0x29] = "UDP .Net Client",
    [0x2a] = "UDP Silverlight Client",
    [0x2b] = "UDP Publisher Client"
}

local statusResponseBytes = {
	[0x00] = "OK",
	[0x01] = "UNMATCHED_SELECTOR"
}

local topicRemovalReasonByBytes = {
	[0x00] = "Unsubscription requested",
	[0x01] = "Control client or server unsubscription",
	[0x02] = "Topic Removal",
	[0x03] = "No longer authorized to access",
	[0x04] = "Unknown reason",
	[0x05] = "Back pressure detected"
}

local updateSourceStateByBytes = {
	[0x00] = "Init",
	[0x01] = "Active",
	[0x02] = "Closed",
	[0x03] = "Standby"
}

local updateTypeByBytes = {
	[0x00] = "Content",
	[0x01] = "Paged, ordered record",
	[0x02] = "Paged, unordered record",
	[0x03] = "Paged, ordered string",
	[0x04] = "Paged, unordered string"
}

local updateActionByBytes = {
	[0x00] = "Update",
	[0x01] = "Replace"
}

local detailTypeByBytes = {
	[0x00] = "Summary",
	[0x01] = "Location",
	[0x02] = "Connector name",
	[0x03] = "Server name"
}

local sessionDetailsEventByBytes = {
	[0x7e] = "Open",
	[0x7f] = "Update",
	[0x00] = "Close",
	[0x01] = "Close",
	[0x02] = "Close",
	[0x03] = "Close",
	[0x04] = "Close",
	[0x05] = "Close",
	[0x06] = "Close",
	[0x07] = "Close",
	[0x08] = "Close",
	[0x09] = "Close",
	[0x0a] = "Close",
	[0x0b] = "Close"
}

local closeReasonByBytes = {
	[0x00] = "Connection lost",
	[0x01] = "IO Exception",
	[0x02] = "Client unresponsive",
	[0x03] = "Message queue limit reached",
	[0x04] = "Closed by client",
	[0x05] = "Message too large",
	[0x06] = "Internal error",
	[0x07] = "Invalid inbound message",
	[0x08] = "Aborted",
	[0x09] = "Lost messages",
	[0x0a] = "Server closing",
	[0x0b] = "Closed by controller",
	[0x0c] = "Failed over"
}

local v5ClientTypeByBytes = {
	[0x00] = "JavaScrip Browser",
	[0x01] = "JavaScrip Flash",
	[0x02] = "JavaScrip Silverlight",
	[0x03] = "Android",
	[0x04] = "iOS",
	[0x05] = "J2ME",
	[0x06] = "Flash",
	[0x07] = "Silverlight",
	[0x08] = "Java",
	[0x09] = ".NET",
	[0x0a] = "C",
	[0x0b] = "Internal"
}

local transportTypeByBytes = {
	[0x00] = "WebSocket",
	[0x01] = "HTTP Long Poll",
	[0x02] = "IFrame Long Poll",
	[0x03] = "IFrame Streaming",
	[0x04] = "DPT",
	[0x05] = "HTTP Streaming",
	[0x06] = "HTTP Duplex",
	[0x07] = "Other"
}

local addressTypeByBytes = {
	[0x01] = "Global",
	[0x02] = "Local",
	[0x03] = "Loopback",
	[0x04] = "Unknown"
}

local booleanByBtyes = {
	[0x00] = "False",
	[0x01] = "True"
}

local throttlerTypeByBytes = {
	[0x00] = "UNTHROTTLED",
	[0x01] = "MESSAGE_PER_SECOND",
	[0x02] = "BYTES_PER_SECOND",
	[0x03] = "MESSAGE_INTERVAL",
	[0x04] = "BUFFER_INTERVAL"
}

local deltaType = {
	[0x0] = "BINARY"
}

local updateResponseByBytes = {
	[0x0] = "SUCCESS",
	[0x1] = "INCOMPATIBLE_UPDATE",
	[0x2] = "UPDATE_FAILED",
	[0x3] = "INVALID_UPDATER",
	[0x4] = "MISSING_TOPIC",
	[0x5] = "INVALID_UPDATER",
	[0x6] = "EXCLUSIVE_UPDATER_CONFLICT",
	[0x7] = "INCOMPATIBLE_UPDATE",
	[0x8] = "DELTA_WITHOUT_VALUE",
	[0x9] = "CLUSTER_REPARTITION",
	[0xa] = "INCOMPATIBLE_STATE"
}

local updateModeByByte = {
	[0x01] = "PARTIAL",
	[0x02] = "FULL"
}

local addTopicResult = {
	[0x00] = "CREATED",
	[0x01] = "EXISTS"
}

local topicNotificationType = {
	[0x0] = "ADDED",
	[0x1] = "SELECTED",
	[0x2] = "REMOVED",
	[0x3] = "DESELECTED"
}

local clientTypesByChar = {
	["J"] = "Java Client",
	["N"] = "HTTP .Net Client",
	["WN"] = "WebSocket .Net Client",
	["F"] = "Flash Bridge Client",
	["S"] = "Silverlight Bridge Client",
	["B"] = "HTTP Browser Client",
	["WJ"] = "WebSocket Java Client",
	["WB"] = "WebSocket Browser Client",
	["I"] = "Introspector Client",
	["WI"] = "WebSocket Introspector Client",
	["W"] = "HTTP Windows Phone Client",
	["F"] = "Flash Client",
	["CA"] = "Flash Comet (HTTPC) Client",
	["FA"] = "HTTP Flash Client",
	["SA"] = "HTTP Silverlight Client",
	["BS"] = "IFrame Streaming Client"
}

-- Package footer
master.const = {
    topicTypes = topicTypes,
    ordering = ordering,
    duplicates = duplicates,
    order = order,
    ruleType = ruleType,
    topicProperty = topicProperty,
    olderTopicProperty = olderTopicProperty,
    responseCodes = responseCodes,
    capabilities = capabilities,
    encodingTypesByValue = encodingTypesByValue,
    clientTypesByValue = clientTypesByValue,
    statusResponseBytes = statusResponseBytes,
    topicRemovalReasonByBytes = topicRemovalReasonByBytes,
    updateSourceStateByBytes = updateSourceStateByBytes,
    updateTypeByBytes = updateTypeByBytes,
    updateActionByBytes = updateActionByBytes,
    detailTypeByBytes = detailTypeByBytes,
    sessionDetailsEventByBytes = sessionDetailsEventByBytes,
    closeReasonByBytes = closeReasonByBytes,
    v5ClientTypeByBytes = v5ClientTypeByBytes,
    transportTypeByBytes = transportTypeByBytes,
    addressTypeByBytes = addressTypeByBytes,
    booleanByBtyes = booleanByBtyes,
    throttlerTypeByBytes = throttlerTypeByBytes,
    deltaType = deltaType,
    updateResponseByBytes = updateResponseByBytes,
    updateModeByByte = updateModeByByte,
    addTopicResult = addTopicResult,
    topicNotificationType = topicNotificationType,
    clientTypesByChar = clientTypesByChar,
    TOPIC_VALUE_MESSAGE_TYPE = 0x04,
    TOPIC_DELTA_MESSAGE_TYPE = 0x05,
    DIFFUSION_MAGIC_NUMBER = 0x23
}
diffusion = master
return master.const
