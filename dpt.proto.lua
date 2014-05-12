
-- Proto package
-- This package sets up the protocol description, fields and value mappings used by Wireshark.

-- Package header
local master = diffusion or {}
if master.proto ~= nil then
	return master.proto
end

local v5 = diffusion.v5

local dptProto = Proto( "DPT", "Diffusion Protocol over TCP")

local responseCodes = {
    [100] = "OK - Connection Successful", 
    [101] = "Invalid Connection Protocol",
    [103] = "One or more of the specified topics are invalid",
    [105] = "Reconnection Successful",
    [110] = "Topic already exists",
    [110] = "Connection Rejected",
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
    [0x0f] = "Supports encrypted, compressed, base 64 encoded data messages and is a feature based client"
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
    [1] = "Event Publisher",
    [2] = "External Publisher",
    [0x10] = "Publisher",
    [0x14] = "Default type",
    [0x15] = "Java",
    [0x16] = ".NET",
    [0x17] = "Flash (Plugin)",
    [0x18] = "Silverlight (Plugin)",
    [0x19] = "iPhone",
    [0x1a] = "J2ME",
    [0x1b] = "Android",
    [0x1c] = "Blackberry",
    [0x1d] = "C",
    [0x1e] = "Perl",
    [0x1f] = "Introspector"
}

local topicTypeBytes = {
	[0x01] = "STATELESS",
	[0x02] = "DELEGATED",
	[0x03] = "SINGLE_VALUE",
	[0x04] = "RECORD",
	[0x05] = "PROTOCOL_BUFFER",
	[0x06] = "CUSTOM",
	[0x07] = "SLAVE",
	[0x08] = "SERVICE",
	[0x09] = "PAGED_STRING",
	[0x10] = "PAGED_RECORD",
	[0x11] = "TOPIC_NOTIFY",
	[0x12] = "ROUTING",
	[0x13] = "CHILD_LIST"
}

local statusResponseBytes = {
	[0x00] = "OK",
	[0x01] = "UNMATCHED_SELECTOR",
}

-- Connection negotiation fields
dptProto.fields.connectionMagicNumber = ProtoField.uint8( "dpt.connection.magicNumber", "Magic number" , base.HEX )
dptProto.fields.connectionProtoNumber = ProtoField.uint8( "dpt.connection.protocolVersion", "Protocol number" )
dptProto.fields.connectionType = ProtoField.uint8( "dpt.connection.connectionType", "Connection Type", base.HEX, clientTypesByValue )
dptProto.fields.capabilities = ProtoField.uint8( "dpt.connection.capabilities", "Client Capabilities", base.HEX, capabilities )
dptProto.fields.connectionResponse = ProtoField.uint8( "dpt.connection.responseCode", "Connection Response", base.DEC, responseCodes )
dptProto.fields.clientID = ProtoField.string( "dpt.clientID", "Client ID" )
dptProto.fields.direction = ProtoField.string( "dpt.direction", "Direction" )

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
dptProto.fields.metadata = ProtoField.string( "dpt.service.metadata", "Metadata" )
dptProto.fields.topicId = ProtoField.uint32( "dpt.service.metadata.topicId", "Topic ID" )
dptProto.fields.topicPath = ProtoField.string( "dpt.service.metadata.topicPath", "Topic Path" )
dptProto.fields.topicType = ProtoField.uint8( "dpt.service.metadata.topicType", "Topic Type", base.HEX, topicTypeBytes )
dptProto.fields.selector = ProtoField.string( "dpt.service.selector", "Topic selector" )
dptProto.fields.status = ProtoField.uint8( "dpt.service.status", "Status", base.HEX, statusResponseBytes )
dptProto.fields.topicName = ProtoField.string( "dpt.service.topicName", "Topic Name" )


-- Package footer
master.proto = {
	dptProto = dptProto,
	statusResponseBytes = statusResponseBytes
}
diffusion = master
return master.proto

