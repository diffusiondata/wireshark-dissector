local dptProto = Proto( "DPT", "Diffusion Protocol over TCP")

local RD, FD = 1, 2
local LENGTH_LEN = 4 -- LLLL
local HEADER_LEN = 2 + LENGTH_LEN -- LLLLTE, usually
local DIFFUSION_MAGIC_NUMBER = 0x23

local f_tcp_stream  = Field.new("tcp.stream")
local f_tcp_dstport = Field.new("tcp.dstport")
local f_tcp_srcport = Field.new("tcp.srcport")
local f_ip_dsthost  = Field.new("ip.dst_host")
local f_ip_srchost  = Field.new("ip.src_host")
local f_frame_number = Field.new("frame.number")

function dump(o)
	if type(o) == 'table' then
	local s = '{ '
	for k,v in pairs(o) do
	if type(k) ~= 'number' then k = '"'..k..'"' end
		s = s .. '['..k..'] = ' .. dump(v) .. ','
	end
		return s .. '} '
	else
		return tostring(o)
	end
end

-- -----------------------------------
-- Create and register a listener for TCP connections

local tcpConnections = {}

function tcpConnections:len()
	local result = 0
	local i,v
	for i,v in pairs( self ) do result = result +1 end
	return result
end

function tcpConnections:isClient( tcpStream, host, port )
	local record = self[tcpStream]
	
	-- Is there a record of this TCP stream?
	if record == nil then return false end
	
	return record.client.ip == host and 
		record.client.port == port
end

local tcpTap = Listener.new( "tcp", "tcp.flags eq 0x12" ) -- listen to SYN,ACK packets (which are sent by the *server*)
function tcpTap.packet( pinfo )
	local streamNumber = f_tcp_stream().value
	local fNumber = f_frame_number().value

	tcpConnections[streamNumber] = { 
		client = { ip = f_ip_dsthost().value, port = pinfo.dst_port }, 
		server = { ip = f_ip_srchost().value, port = pinfo.src_port } }
		
	info( dump( tcpConnections ) )
end

function tcpTap.reset()
	info( "resetting tcpConnections" )
--	tcpConnections = {}
end

-- -----------------------------------
-- The Alias Table
-- TODO: Should the Alias table be based on tcpStreams or the client ID?

local AliasTable = {}

function AliasTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end

function AliasTable:setAlias( tcpStream, alias, topicName )
	-- Get the table for the tcpStream, or create a new one
	local conversation = self[tcpStream] or {}
	conversation[alias] = topicName
	self[tcpStream] = conversation
end

function AliasTable:getAlias( tcpStream, alias )
	local conversation = self[tcpStream]
	if conversation == nil then
		return nil
	end
	return conversation[alias]
end

local aliasTable = AliasTable:new()

-- Parse the first header as a topic
-- Takes the tree node and header range
-- Assumes there will be more than one header
-- Adds the topic to the aliasTable if an alias is present
-- Retrieves the topic from the aliasTable if there is only an alias
-- Adds the topic and alias entries to the dissection tree 
-- Returns the remaining header range, the topic as a string and the alias as a string
-- The remaining header range will be nil if there are no more headers
-- The alias will be nil if there is no alias present in the header
function parseTopicHeader( treeNode, headerRange )
	local topicEndIndex = headerRange:bytes():index( FD )
	local topicExpressionRange

	if topicEndIndex > -1 then
		topicExpressionRange = headerRange:range( 0, topicEndIndex )
		headerRange = headerRange:range( topicEndIndex + 1 )
	else
		topicExpressionRange = headerRange
		headerRange = nil
	end

	local delimIndex = topicExpressionRange:bytes():index( 0x21 )
	local tcpStream = f_tcp_stream().value
	local topicRange = nil
	local aliasRange = nil
	local topic = nil
	local alias = nil
	if delimIndex == 0 then
		aliasRange = topicExpressionRange
		alias = aliasRange:string();

		topic = aliasTable:getAlias( tcpStream, alias )
	elseif delimIndex > -1 then
		topicRange = topicExpressionRange:range( 0, delimIndex )
		aliasRange = topicExpressionRange:range( delimIndex )

		topic = topicRange:string()
		alias = aliasRange:string()

		aliasTable:setAlias( tcpStream, alias, topic )
	else
		topicRange = topicExpressionRange
		topic = topicRange:string()
	end

	-- Add topic entry to dissection tree
	if topicRange ~= nil then
		treeNode:add( dptProto.fields.topic, topicRange, topic )
	elseif topic ~= nil then
		-- Topic from alias table, range expired reuse alias range
		treeNode:add( dptProto.fields.topic, aliasRange, topic ):append_text(" (resolved from alias)")
	end

	-- Add alias entry to dissection tree
	if aliasRange ~= nil then
		treeNode:add( dptProto.fields.alias, aliasRange, alias )
	end

	return headerRange, topic, alias
end

-- -----------------------------------
-- A 'class' to process message types

MessageType = {}

function MessageType:new( id, name, fixedHeaderCount)
	local result = { id = id, name = name, fixedHeaderCount = fixedHeaderCount }
	setmetatable( result, self )
	self.__index = self
	return result
end

-- Iterate across an array of MessageType object, and produce a table of the same indexed by the ID
function MessageType.index( typeArray )
	local result = {}
	for i, type in ipairs(typeArray) do
		result[type.id] = type
	end
	return result
end

-- Populate the headers tree with separate fixed headers and user headers
function MessageType:markupHeaders( treeNode, headerRange )
	-- Find the RD marking the fixed|user boundary
	local headerBreak = headerRange:bytes():indexn( FD, self.fixedHeaderCount -1 )
	if headerBreak == -1 then
		-- no user headers, only fixed headers
		treeNode:add( dptProto.fields.fixedHeaders, headerRange, headerRange:string():escapeDiff() )
	else
		-- fixed headers and user headers
		local fixedHeaderRange = headerRange:range( 0, headerBreak )
		local userHeaderRange = headerRange:range( headerBreak +1 )
		treeNode:add( dptProto.fields.fixedHeaders, fixedHeaderRange, fixedHeaderRange:string():escapeDiff() )
		treeNode:add( dptProto.fields.userHeaders, userHeaderRange, userHeaderRange:string():escapeDiff() )
	end
end

function MessageType:markupBody( messageDetails, parentTreeNode, bodyRange )
	-- the payload, everything after the headers
	local bodyNode = parentTreeNode:add( dptProto.fields.content, bodyRange, string.format( "%d bytes", bodyRange:len() ) )

	if messageDetails.msgEncoding == 0 then
		local rangeBase = 0
		local bodyString = bodyRange:string()
		local records = bodyString:split( string.char( RD ) )

		bodyNode:append_text( string.format(  ", %d records", #records ) )

		-- Break open into records & then fields
		for i,record in ipairs(records) do

			local recordRange = bodyRange:range( rangeBase, #record )
			local recordTree = bodyNode:add( dptProto.fields.record, recordRange, record:toRecordString() )

			rangeBase = rangeBase + #record + 1 -- +1 for the delimiter
		end
	end
end

function MessageType:getDescription( messageDetails )
	return self.name
end

-- Functionality specific to Topic Loads

local topicLoadType = MessageType:new( 0x14, "Topic Load", 1 )

function topicLoadType:markupHeaders( treeNode, headerRange )
	-- Parse topic
	local topic, alias
	headerRange, topic, alias = parseTopicHeader( treeNode, headerRange )

	if alias ~= nil then
		self.loadDescription = string.format( "aliasing %s => topic '%s'", alias, topic )
	else
		self.loadDescription = topic
	end

	if headerRange ~= nil then
		treeNode:add( dptProto.fields.userHeaders, headerRange, headerRange:string():escapeDiff() )
	end
end

function topicLoadType:getDescription( messageDetails )
	return string.format( "%s, %s", self.name, self.loadDescription ) 
end

-- Functionality specific to Delta Messages

local deltaType = MessageType:new( 0x15, "Delta", 1 )

function deltaType:markupHeaders( treeNode, headerRange )
	-- Parse topic
	local topic, alias
	headerRange, topic, alias = parseTopicHeader( treeNode, headerRange )

	if topic ~= nil then
		self.topicDescription = string.format( "Topic: %s", topic )
	else
		self.topicDescription = string.format( "Unknown alias: %s", alias )
	end

	if headerRange ~= nil then
		treeNode:add( dptProto.fields.userHeaders, headerRange, headerRange:string():escapeDiff() )
	end
end

function deltaType:getDescription( messageDetails )
	return string.format( "%s, %s", self.name, self.topicDescription ) 
end

-- Functionality specific to Subscriptions - the info column, mostly

local subscribeType = MessageType:new( 0x16, "Subscribe", 1 )

function subscribeType:markupHeaders( treeNode, headerRange )
	-- A single header, with a topic-selector
	self.subscriptionDescription = string.format( "Subscribe to '%s'", headerRange:string() )
	treeNode:add( dptProto.fields.fixedHeaders, headerRange, self.subscriptionDescription )
end

function subscribeType:getDescription( messageDetails )
	return self.subscriptionDescription 
end

-- Functionality specific to Command Messages
local commandMessageType = MessageType:new( 0x24, "Command Message", 2 )

function commandMessageType:markupHeaders( treeNode, headerRange )
	-- Parse topic
	local topic, alias
	headerRange, topic, alias = parseTopicHeader( treeNode, headerRange )

	local commandEndIndex = headerRange:bytes():index( FD )
	local commandRange
	if commandEndIndex > -1 then
		commandRange = headerRange:range( 0, commandEndIndex )
		treeNode:add( dptProto.fields.command, commandRange, commandRange:string() )

		--Parse parameters
		local parametersRange = headerRange:range( commandEndIndex + 1 )
		treeNode:add( dptProto.fields.parameters, parametersRange, parametersRange:string():escapeDiff() )
	else
		commandRange = headerRange:range( 0 )
		treeNode:add( dptProto.fields.command, commandRange, commandRange:string() )
	end
	if topic ~= nil then
		self.commandDescription = string.format ( "Command Message Topic: %s Command: %s", topic, commandRange:string() )
	elseif alias ~= nil then
		self.commandDescription = string.format ( "Command Message Alias: %s Command: %s", alias, commandRange:string() )
	else
		self.commandDescription = string.format ( "Command Message Topic: Unknown Command: %s", commandRange:string() )
	end
end

function commandMessageType:getDescription( messageDetails )
	return self.commandDescription 
end

-- Functionality specific to Command Topic Load
local commandTopicLoadType = MessageType:new( 0x28, "Command Topic Load", 3 )

function commandTopicLoadType:markupHeaders( treeNode, headerRange )
	-- Parse topic
	local topic, alias
	headerRange, topic, alias = parseTopicHeader( treeNode, headerRange )

	-- Parse command topic category
	local commandTopicCategoryEndIndex = headerRange:bytes():index( FD )
	local commandTopicCategoryRange = headerRange:range( 0, commandTopicCategoryEndIndex )
	treeNode:add( dptProto.fields.commandTopicCategory, commandTopicCategoryRange, commandTopicCategoryRange:string() )

	-- Parse command Topic Type
	headerRange = headerRange:range( commandTopicCategoryEndIndex + 1 )
	local commandTopicTypeEndIndex = headerRange:bytes():index( FD )
	local commandRange
	if commandTopicTypeEndIndex > -1 then
		commandTopicTypeRange = headerRange:range( 0, commandTopicTypeEndIndex )
		treeNode:add( dptProto.fields.commandTopicType, commandTopicTypeRange, commandTopicTypeRange:string() )

		--Parse parameters
		local parametersRange = headerRange:range( commandTopicTypeEndIndex + 1 )
		treeNode:add( dptProto.fields.parameters, parametersRange, parametersRange:string():escapeDiff() )
	else
		commandTopicTypeRange = headerRange:range( 0 )
		treeNode:add( dptProto.fields.commandTopicType, commandTopicTypeRange, commandTopicTypeRange:string() )
	end
	if topic ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Load Topic: %s Topic Category: %s", topic, commandTopicCategoryRange:string() )
	elseif alias ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Load Alias: %s Topic Category: %s", alias, commandTopicCategoryRange:string() )
	else
		self.commandTopicLoadDescription = string.format ( "Command Load Topic: Unknown Topic Category: %s", commandTopicCategoryRange:string() )
	end
end

function commandTopicLoadType:getDescription( messageDetails )
	return self.commandTopicLoadDescription 
end

-- Functionality specific to Command Topic Notification
local commandTopicNotificationType = MessageType:new( 0x29, "Command Topic Notification", 2 )

function commandTopicNotificationType:markupHeaders( treeNode, headerRange )
	-- Parse topic
	local topic
	local alias
	headerRange, topic, alias = parseTopicHeader( treeNode, headerRange )

	-- Parse notification type
	local notificationTypeEndIndex = headerRange:bytes():index( FD )
	local notificationTypeRange
	if notificationTypeEndIndex > -1 then
		notificationTypeRange = headerRange:range( 0, notificationTypeEndIndex )
		treeNode:add( dptProto.fields.notificationType, notificationTypeRange, notificationTypeRange:string() )

		--Parse parameters
		local parametersRange = headerRange:range( notificationTypeEndIndex + 1 )
		treeNode:add( dptProto.fields.parameters, parametersRange, parametersRange:string():escapeDiff() )
	else
		notificationTypeRange = headerRange:range( 0 )
		treeNode:add( dptProto.fields.notificationType, notificationTypeRange, notificationTypeRange:string() )
	end
	if topic ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Notification Topic: %s Notification Type: %s", topic, notificationTypeRange:string() )
	elseif alias ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Notification Alias: %s Notification Type: %s", alias, notificationTypeRange:string() )
	else
		self.commandTopicLoadDescription = string.format ( "Command Notification Topic: Unknown Notification Type: %s", notificationTypeRange:string() )
	end
end

function commandTopicNotificationType:getDescription( messageDetails )
	return self.commandTopicLoadDescription 
end

-- The messageType table

local messageTypesByValue = MessageType.index( {
	topicLoadType,
	deltaType,
	subscribeType,
	MessageType:new( 0x17, "Unsubscribe", 1 ),
	MessageType:new( 0x18, "Ping Server", 2 ), 
	MessageType:new( 0x19, "Ping Client", 1 ),
	MessageType:new( 0x1a, "Credentials", 2 ),
	MessageType:new( 0x1b, "Credentials Rejected", 2 ),
	MessageType:new( 0x1c, "Abort Notification", 0 ),
	MessageType:new( 0x1d, "Close Request", 0 ),
	MessageType:new( 0x1e, "Topic Load - ACK Required", 2), 
	MessageType:new( 0x1f, "Delta - ACK Required", 2 ),
	MessageType:new( 0x20, "ACK - acknowledge", 1 ),
	MessageType:new( 0x21, "Fetch", 1 ),
	MessageType:new( 0x22, "Fetch Reply", 1 ),
	MessageType:new( 0x23, "Topic Status Notification", 2 ),
	commandMessageType,
	commandTopicLoadType,
	commandTopicNotificationType,
	MessageType:new( 0x30, "Cancel Fragmented Message Set", 1 )
} )

function MessageType.nameByID(byte)
	if( byte >= 0x40 ) then
		return nameByID(byte - 0x40) .. " fragmented"
	else
		return messageTypesByValue[byte].name
	end
end

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
	--TODO: Generate these values from ConnectionTypes.xml
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

-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
function ByteArray:indexn(ch, delimiterCount)
	for i = 0, self:len()-1 do
		if self:get_index( i ) == ch then 
			-- Found a match, but is it the right one?
			if delimiterCount == 0 then
				return i
			end
			delimiterCount = delimiterCount -1
		end
	end
	return -1
end

-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
function ByteArray:index(ch)
	for i = 0, self:len()-1 do
		if self:get_index( i ) == ch then return i end
	end
	return -1
end

-- Mark up non-printing delimiters
function string:escapeDiff()
	local result = self:gsub( string.char(RD), "<RD>" )
	return (result:gsub( string.char(FD), "<FD>" ))
end

function string:toRecordString() 
	return string.format( "[%s]", self:gsub( string.char(FD), ", " ) )
end

-- Split a string into fields by the given delimited
function string:split(sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

-- Dissect the connection negotiation messages
local function dissectConnection( tvb, pinfo, tree )
	local messageTree = tree:add( dptProto, tvb() )
	local offset = 0
	
	-- Is this a client or server packet?
	local tcpStream, host, port = f_tcp_stream().value, f_ip_srchost().value, f_tcp_srcport().value
	local isClient = tcpConnections:isClient( tcpStream, host, port ) 

	-- Get the magic number 
	local magicNumberRange = tvb( offset, 1 )
	local magicNumber = magicNumberRange:uint()
	messageTree:add( dptProto.fields.connectionMagicNumber, magicNumberRange )
	offset = offset +1
	
	-- get the protocol version number
	local protoVerRange = tvb( offset, 1 )
	local protoVersion = protoVerRange:uint()
	messageTree:add( dptProto.fields.connectionProtoNumber, protoVerRange )
	offset = offset +1
	
	if isClient then
		pinfo.cols.info = string.format( "Connection request" )
		
		-- the 1 byte connection type
		local connectionTypeRange = tvb( offset, 1 )
		local connectionType = connectionTypeRange:uint()
		messageTree:add( dptProto.fields.connectionType, connectionTypeRange )
		offset = offset +1
		
		-- the 1 byte capabilities value
		local capabilitiesRange = tvb( offset, 1 )
		messageTree:add( dptProto.fields.capabilities, capabilitiesRange )
		offset = offset +1
		
		-- TODO: load credentials <RD> data <MD>
		local range = tvb( offset )
		local rdBreak = range:bytes():index( RD )
		if rdBreak >= 0 then
			-- Mark up the creds - if there are any
			local credsRange = range(0, rdBreak )
			local creds = credsRange:string():toRecordString()
			if credsRange:len() > 0 then
				messageTree:add( dptProto.fields.loginCreds, credsRange, creds )
			end

			-- Mark up the login topicset - if there are any
			local topicsetRange = range( rdBreak +1, ( range:len() -2 ) -rdBreak ) -- fiddly handling of trailing null character
			if topicsetRange:len() > 0 then
				messageTree:add( dptProto.fields.loginTopics, topicsetRange )
			end
			
		end

	else
		-- Is a server response
		pinfo.cols.info = string.format( "Connection response" )
		
		local connectionResponseRange = tvb( offset, 1 )
		local connectionResponse = connectionResponseRange:uint()
		messageTree:add( dptProto.fields.connectionResponse, connectionResponseRange )
		offset = offset +1
		
		-- The size field
		local messageLengthSizeRange = tvb( offset, 1 )
		local messageLengthSize = messageLengthSizeRange:uint()
		messageTree:add( dptProto.fields.messageLengthSize, messageLengthSizeRange ) 
		offset = offset +1
		
		-- the client ID (the rest of this)
		local clientIDRange = tvb( offset, (tvb:len() -1) -offset )  -- fiddly handling of trailing null character
		local clientID = clientIDRange:string()
		messageTree:add( dptProto.fields.clientID, clientIDRange )
		
	end
	
	
	--TODO: dissect this as a client or as a server packet
end

-- Process an individual DPT message
local function processMessage( tvb, pinfo, tree, offset ) 
	local msgDetails = {}

	local tcpStream = f_tcp_stream().value -- get the artificial 'tcp stream' number

	-- Assert there is enough to parse even the LLLL segment
	if offset + LENGTH_LEN >  tvb:len() then
		-- Signal Wireshark that more bytes are needed
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT -- Using LENGTH_LEN gets us into trouble 
		return -1
	end

	-- Get the size word
	local messageStart = offset
	local msgSizeRange = tvb( offset, LENGTH_LEN )
	msgDetails.msgSize = msgSizeRange:uint()
	offset = offset +4

	-- Assert there is enough to parse - having read LLLL
	local messageContentLength = ( msgDetails.msgSize - LENGTH_LEN )
	if offset + messageContentLength > tvb:len() then
		-- Signal Wireshark that more bytes are needed
		pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		return -1
	end

	-- Get the type byte
	local msgTypeRange = tvb( offset, 1 )
	msgDetails.msgType = msgTypeRange:uint()
	offset = offset +1
	
	-- Get the encoding byte
	local msgEncodingRange = tvb( offset, 1 )
	msgDetails.msgEncoding = msgEncodingRange:uint()
	offset = offset +1

	-- Add to the GUI the size-header, type-header & encoding-header
	local messageRange = tvb( messageStart, msgDetails.msgSize )
	local messageTree = tree:add( dptProto, messageRange )

	messageTree:add( dptProto.fields.sizeHdr, msgSizeRange )
	local typeNode = messageTree:add( dptProto.fields.typeHdr, msgTypeRange )
	local messageTypeName = MessageType.nameByID( msgDetails.msgType )
	typeNode:append_text( " = " .. messageTypeName )
	messageTree:add( dptProto.fields.encodingHdr, msgEncodingRange )

	-- The content range
	local contentSize = msgDetails.msgSize - HEADER_LEN
	local contentRange = tvb( offset, contentSize )
	local contentNode = messageTree:add( dptProto.fields.content, contentRange, string.format( "%d bytes", contentSize ) )

	offset = offset + contentSize
	local messageType = messageTypesByValue[msgDetails.msgType]

	-- The headers & body -- find the 1st RD in the content
	local headerBreak = contentRange:bytes():index( RD )
	if headerBreak >= 0 then
		local headerRange = contentRange:range( 0, headerBreak )
		local headerNode = contentNode:add( dptProto.fields.headers, headerRange, string.format( "%d bytes", headerBreak ) )

		-- Pass the header-node to the MessageType for further processing
		messageType:markupHeaders( headerNode, headerRange )

		if headerBreak +1 <= (contentRange:len() -1) then
			-- Only markup up the body if there is one (there needn't be)
			local bodyRange = contentRange:range( headerBreak +1 )

			messageType:markupBody( msgDetails, contentNode, bodyRange )
		end
	end
	
	-- Set the Info column of the tabular display -- NB: this must be called last
	pinfo.cols.info = messageType:getDescription( messageDetails )

	return offset
end

function dptProto.init()
	info( "dptProto.init()" )
	aliasTable = AliasTable:new()
end

function dptProto.dissector( tvb, pinfo, tree )

	-- Set the tabular display
	pinfo.cols.protocol = dptProto.name

	-- Is this a connection negotiation?
	local firstByte = tvb( 0, 1 ):uint()
	if( firstByte == DIFFUSION_MAGIC_NUMBER ) then
		-- process & skip over it, if it is.
		return dissectConnection( tvb, pinfo, tree )
	end

	local offset, messageCount = 0, 0
	repeat
		-- -1 indicates incomplete read
		 offset = processMessage( tvb, pinfo, tree, offset )
		 messageCount = messageCount +1
	until ( offset == -1 or offset >= tvb:len() )
	
	-- Summarise
	if messageCount > 1 then
		pinfo.cols.info = string.format( "%d messages", messageCount )
	end
end

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
	[0x0f] = "Supports encrypted, compressed, base 64 encoded data messages and is a control client"
}

-- Connection negotiation fields
dptProto.fields.connectionMagicNumber = ProtoField.uint8( "diffusion.connection.magicNumber", "Magic number" , base.HEX )
dptProto.fields.connectionProtoNumber = ProtoField.uint8( "diffusion.connection.protoNumber", "Protocol number" )
dptProto.fields.connectionType = ProtoField.uint8( "diffusion.connection.connectionType", "Connection Type", base.HEX, clientTypesByValue )

-- Message fields
dptProto.fields.sizeHdr = ProtoField.uint32( "dptProto.size", "Size" )
dptProto.fields.typeHdr = ProtoField.uint8( "dptProto.type", "Type", base.HEX ) -- no lookup table possible here, it's a bitfield
dptProto.fields.encodingHdr = ProtoField.uint8( "dptProto.encoding", "Encoding", base.HEX, encodingTypesByValue )
dptProto.fields.headers = ProtoField.string( "dptProto.headers", "Headers" )
dptProto.fields.userHeaders = ProtoField.string( "dptProto.userHeaders", "User headers" )
dptProto.fields.fixedHeaders = ProtoField.string( "dptProto.fixedHeaders", "Fixed headers" )
dptProto.fields.content = ProtoField.string( "dptProto.content", "Content" )
dptProto.fields.topic = ProtoField.string( "dptProto.field.topic", "Topic" )
dptProto.fields.alias = ProtoField.string( "dptProto.field.alias", "Alias" )

-- Command message fields
dptProto.fields.command =  ProtoField.string( "dptProto.field.command", "Command" )
dptProto.fields.parameters = ProtoField.string( "dptProto.field.parameters", "Parameters" )
dptProto.fields.commandTopicType = ProtoField.string( "dptProto.field.commandTopicType", "Topic Type" )
dptProto.fields.commandTopicCategory = ProtoField.string( "dptProto.field.commandTopicCategory", "Topic Category" )
dptProto.fields.notificationType = ProtoField.string( "dptProto.field.notificationType", "Notification Type" )

dptProto.fields.connectionResponse = ProtoField.uint8( "dptProto.connectionResponse", "Connection Response", base.DEC, responseCodes )
dptProto.fields.messageLengthSize = ProtoField.uint8( "dptProto.messageLengthSize", "Size Length", base.DEC )
dptProto.fields.clientID = ProtoField.string( "dptProto.field.clientID", "Client ID" )
dptProto.fields.capabilities = ProtoField.uint8( "dptProto.capabilities", "Client Capabilities", base.HEX, capabilities )
dptProto.fields.loginCreds = ProtoField.string( "dptProto.field.loginCreds", "Login Credentials" )
dptProto.fields.loginTopics = ProtoField.string( "dptProto.field.loginTopics", "Subscriptions" )

-- Register the dissector
tcp_table = DissectorTable.get( "tcp.port" )
tcp_table:add( 8080, dptProto )

