
-- Proto package
-- This package sets up the protocol description, fields and value mappings used by Wireshark.

-- Package header
local master = diffusion or {}
if master.proto ~= nil then
	return master.proto
end

local v5 = diffusion.v5

local dptProto = Proto( "DPT", "Diffusion Protocol")

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

local topicTypesByByte = {
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
    [0x0d] = "CHILD_LIST"
}

local statusResponseBytes = {
	[0x00] = "OK",
	[0x01] = "UNMATCHED_SELECTOR"
}

local topicRemovalReasonByBytes = {
	[0x00] = "Unsubscription requested",
	[0x01] = "Control client or server unsubscription",
	[0x02] = "Topic Removal",
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
	[0x0b] = "Closed by controller"
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

-- Connection negotiation fields
dptProto.fields.connectionMagicNumber = ProtoField.uint8( "dpt.connection.magicNumber", "Magic number" , base.HEX )
dptProto.fields.connectionProtoNumber = ProtoField.uint8( "dpt.connection.protocolVersion", "Protocol version" )
dptProto.fields.connectionType = ProtoField.uint8( "dpt.connection.connectionType", "Connection Type", base.HEX, clientTypesByValue )
dptProto.fields.capabilities = ProtoField.uint8( "dpt.connection.capabilities", "Client Capabilities", base.HEX, capabilities )
dptProto.fields.connectionResponse = ProtoField.uint8( "dpt.connection.responseCode", "Connection Response", base.DEC, responseCodes )
dptProto.fields.clientID = ProtoField.string( "dpt.clientID", "Client ID" )
dptProto.fields.direction = ProtoField.string( "dpt.direction", "Direction" )
dptProto.fields.wsConnectionProtoNumber= ProtoField.string( "dpt.ws.connection.protocolVersion", "Protocol version" )
dptProto.fields.wsConnectionType = ProtoField.string( "dpt.ws.connection.connectionType", "Connection Type" )
dptProto.fields.wsPrincipal = ProtoField.string( "dpt.ws.connection.principal", "Principal")
dptProto.fields.wsCredentials = ProtoField.string( "dpt.ws.connection.credentials", "Credentials")
dptProto.fields.sessionId = ProtoField.string( "dpt.connection.sessionId", "Session Id")
dptProto.fields.sessionToken = ProtoField.string( "dpt.connection.sessionToken", "Session Token")

-- Message fields
dptProto.fields.typeHdr = ProtoField.uint8( "dpt.message.type", "Type", base.HEX ) -- no lookup table possible here, it's a bitfield
dptProto.fields.encodingHdr = ProtoField.uint8( "dpt.message.encoding", "Encoding", base.HEX, encodingTypesByValue )
dptProto.fields.topic = ProtoField.string( "dpt.header.topic", "Topic" )
dptProto.fields.alias = ProtoField.string( "dpt.header.alias", "Alias" )
dptProto.fields.headers = ProtoField.string( "dptProto.headers", "Headers" )
dptProto.fields.userHeaders = ProtoField.string( "dptProto.userHeaders", "User headers" )
dptProto.fields.fixedHeaders = ProtoField.string( "dptProto.fixedHeaders", "Fixed headers" )
dptProto.fields.content = ProtoField.string( "dptProto.content", "Content" )
dptProto.fields.connection = ProtoField.string( "dptProto.connection", "Connection" )
dptProto.fields.sizeHdr = ProtoField.uint32( "dptProto.size", "Size" )
dptProto.fields.messageLengthSize = ProtoField.uint8( "dptProto.messageLengthSize", "Size Length", base.DEC )

dptProto.fields.record = ProtoField.string( "dpt.records" )
dptProto.fields.field = ProtoField.string( "dpt.fields" )

-- Command message fields
dptProto.fields.command =  ProtoField.string( "dpt.header.command", "Command" )
dptProto.fields.commandTopicType = ProtoField.string( "dpt.header.command.topicType", "Topic Type" )
dptProto.fields.commandTopicCategory = ProtoField.string( "dpt.header.command.topicCategory", "Topic Category" )
dptProto.fields.notificationType = ProtoField.string( "dpt.header.command.notificationType", "Notification Type" )
dptProto.fields.parameters = ProtoField.string( "dptProto.field.parameters", "Parameters" )

dptProto.fields.loginCreds = ProtoField.string( "dptProto.field.loginCreds", "Login Credentials" )
dptProto.fields.loginTopics = ProtoField.string( "dptProto.field.loginTopics", "Subscriptions" )

-- Ping message fields
dptProto.fields.timestamp = ProtoField.string( "dpt.header.timestamp", "Timestamp" )
dptProto.fields.queueSize = ProtoField.string( "dpt.header.queueSize", "Message Queue size" )

-- Ack message field
dptProto.fields.ackId = ProtoField.string( "dpt.header.ackId", "Acknowledgement ID" )

-- Service fields
dptProto.fields.service = ProtoField.string( "dpt.service", "Service" )
dptProto.fields.serviceIdentity = ProtoField.uint8( "dpt.service.identity", "Service Identity", base.HEX, v5.serviceIdentity )
dptProto.fields.serviceMode = ProtoField.uint8( "dpt.service.mode", "Mode", base.HEX, v5.modeValues )
dptProto.fields.conversation = ProtoField.uint32( "dpt.conversation.id", "Conversation ID" )
dptProto.fields.topicInfo = ProtoField.string( "dpt.service.topicInfo", "Topic Info" )
dptProto.fields.topicId = ProtoField.uint32( "dpt.service.topicInfo.topicId", "Topic ID" )
dptProto.fields.topicPath = ProtoField.string( "dpt.service.topicInfo.topicPath", "Topic Path" )
dptProto.fields.topicType = ProtoField.uint8( "dpt.service.topicInfo.topicType", "Topic Type", base.HEX, topicTypesByByte )
dptProto.fields.selector = ProtoField.string( "dpt.service.selector", "Topic selector" )
dptProto.fields.status = ProtoField.uint8( "dpt.service.status", "Status", base.HEX, statusResponseBytes )
dptProto.fields.topicName = ProtoField.string( "dpt.service.topicName", "Topic Name" )
dptProto.fields.topicUnSubReason = ProtoField.uint8( "dpt.service.topicUnsubscribeReason", "Reason", base.HEX, topicRemovalReasonByBytes )
dptProto.fields.responseTime = ProtoField.string( "dpt.service.responseTime", "Response time" )
dptProto.fields.handlerName = ProtoField.string( "dpt.service.handlerName", "Handler name" )
dptProto.fields.controlGroup = ProtoField.string( "dpt.service.controlGroup", "Control group" )
dptProto.fields.regServiceId = ProtoField.uint8( "dpt.service.regServiceId", "Registration Service Identity", base.HEX, v5.serviceIdentity )
dptProto.fields.handlerTopicPath = ProtoField.string( "dpt.service.handlerTopicPath", "Handler topic path" )
dptProto.fields.updateSourceTopicPath = ProtoField.string( "dpt.service.updateSourceTopicPath", "Update source topic path" )
dptProto.fields.oldUpdateSourceState = ProtoField.uint8( "dpt.service.updateSourceState.old", "Old update source state", base.HEX, updateSourceStateByBytes )
dptProto.fields.newUpdateSourceState = ProtoField.uint8( "dpt.service.updateSourceState", "New update source state", base.HEX, updateSourceStateByBytes )
dptProto.fields.updateType = ProtoField.uint8( "dpt.service.updateType", "Update type", base.HEX, updateTypeByBytes )
dptProto.fields.updateAction = ProtoField.uint8( "dpt.service.updateAction", "Update action", base.HEX, updateActionByBytes )
dptProto.fields.contentLength = ProtoField.uint32( "dptProto.content.length", "Content length", base.DEC )

-- Session listener registration
dptProto.fields.sessionListenerRegistration = ProtoField.string( "dpt.service.sessionListenerRegistration", "Session listener registration" )
dptProto.fields.detailTypeSet = ProtoField.string( "dpt.service.detailTypeSet", "Detail type set" )
dptProto.fields.detailType = ProtoField.uint8( "dpt.service.detailType", "Detail type", base.HEX, detailTypeByBytes )

-- Session listener notifications
dptProto.fields.sessionListenerEvent = ProtoField.string( "dpt.service.sessionListenerEvent", "Session listener event" )
dptProto.fields.sessionListenerEventType = ProtoField.uint8( "dpt.service.sessionListenerEventType", "Event type", base.HEX, sessionDetailsEventByBytes )
dptProto.fields.closeReason = ProtoField.uint8( "dpt.service.closeReason", "Close reason", base.HEX, closeReasonByBytes )
dptProto.fields.serviceSessionId = ProtoField.string( "dpt.service.sessionId", "Session Id")
dptProto.fields.sessionDetails = ProtoField.string( "dpt.service.sessionDetails", "Session Details" )
dptProto.fields.summary = ProtoField.string( "dpt.service.summary", "Summary" )
dptProto.fields.servicePrincipal = ProtoField.string( "dpt.service.principal", "Principal")
dptProto.fields.clientType = ProtoField.uint8( "dpt.service.clientType", "Client type", base.HEX, v5ClientTypeByBytes)
dptProto.fields.transportType = ProtoField.uint8( "dpt.service.transportType", "Transport type", base.HEX, transportTypeByBytes)
dptProto.fields.location = ProtoField.string( "dpt.service.location", "Location" )
dptProto.fields.address = ProtoField.string( "dpt.service.address", "Address" )
dptProto.fields.hostName = ProtoField.string( "dpt.service.hostName", "Hostname" )
dptProto.fields.resolvedName = ProtoField.string( "dpt.service.resolvedName", "Resolved name" )
dptProto.fields.addressType = ProtoField.uint8( "dpt.service.addressType", "Address type", base.HEX, addressTypeByBytes )
dptProto.fields.country = ProtoField.string( "dpt.service.country", "Country" )
dptProto.fields.language = ProtoField.string( "dpt.service.language", "Language" )
dptProto.fields.connectorName = ProtoField.string( "dpt.service.connectorName", "Connector name" )
dptProto.fields.serverName = ProtoField.string( "dpt.service.serverName", "Server name" )


-- Package footer
master.proto = {
	dptProto = dptProto,
	statusResponseBytes = statusResponseBytes
}
diffusion = master
return master.proto

