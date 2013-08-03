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

-- The Alias Table
AliasTable = {}

function AliasTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end

function AliasTable.setAlias( tcpStream, alias, topicName )
	-- Get the table for the tcpStream, or create a new one
	local conversation = self[tcpStream] or {}
	conversation[alias] = topicName
	self[tcpStream] = conversation
end

function AliasTable.getAlias( tcpStream, alias )
	local conversation = self[tcpStream]
	if conversation == nil then
		return nil
	end
	return conversation[alias]
end

local aliasTable = AliasTable:new()

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

-- Populate the headers tree with seperate fixed headers and user headers
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
			local recordTree = bodyNode:add( diffusionProto.fields.record, recordRange, record:toRecordString() )
							
			rangeBase = rangeBase + #record + 1 -- +1 for the delimiter
		end	
	end
end

function MessageType:getDescription( messageDetails )
	return self.name
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

-- Functionality specific to Topic Loads

local topicLoadType = MessageType:new( 0x14, "Topic Load", 1 )

function topicLoadType:markupHeaders( treeNode, headerRange )
	-- FIXME: this does not handle user-headers, and assumes there will be only one header - bleh
	-- A single header, with a topic-name, or a name&alias pair
	local topicExpression = headerRange:string()
	local delimIndex = topicExpression:find( "!" )
	if delimIndex == nil then
		-- No alias binding
		self.loadDescription = topicExpression
	else
		local expressionPieces = topicExpression:split( '!' )
		local topicName = expressionPieces[1]
		local topicAlias = expressionPieces[2]
		self.loadDescription = string.format( "aliasing %s => topic '%s'", topicAlias, topicName )
		
		-- TODO: bind this alias in the AliasTable
	end
	
	treeNode:add( dptProto.fields.fixedHeaders, headerRange, self.loadDescription )
end

function topicLoadType:getDescription( messageDetails )
	return string.format( "%s, %s", self.name, self.loadDescription ) 
end 



-- The messageType table

local messageTypesByValue = MessageType.index( {
	topicLoadType,
	MessageType:new( 0x15, "Delta", 1 ),
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
	MessageType:new( 0x24, "Command Message", 2 ),
	MessageType:new( 0x28, "Command Topic Load", 3 ),
	MessageType:new( 0x29, "Command Topic Notification", 2 ),
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
	--TODO: Generate these values from the central XML
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
	[0x1e] = "Perl"
}


-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
function ByteArray:indexn(ch, delimiterCount)
	for i = 0, self:len()-1 do
--			info( string.format( "ByteArray:index( '" .. ch .. "', ".. delimiterCount.." ), i=" .. i.. ", self:len()=" .. self:len() ) )
		if self:get_index( i ) == ch then 
			-- Found a match, but is it the right one?
			if delimiterCount == 0 then
--					info( "ByteArray:index() returning " .. i )
				return i
			end
			delimiterCount = delimiterCount -1
		end
	end
--		info( "ByteArray:indexn() returning -1" )
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
--TODO: need to be able to tell which peer is speaking, so I can interpret accordingly
local function dissect_connection( tvb, pinfo, tree )
	local messageTree = tree:add( dptProto, tvb() )
	local offset = 0
	
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
	
	-- the 1 byte connection type
	local connectionTypeRange = tvb( offset, 1 )
	local connectionType = connectionTypeRange:uint()
	local treeNode = messageTree:add( dptProto.fields.connectionType, connectionTypeRange )
	treeNode:append_text( string.format( " = %s", clientTypesByValue[connectionType] or string.format( "Unknown value %d", connectionType ) ) )
	
	pinfo.cols.info = string.format( "Connection negotiation, protocol=v%d", protoVersion )
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
	local msgEncodingStr = encodingTypesByValue[msgDetails.msgEncoding] or "Unknown encoding"
	offset = offset +1

	-- Add to the GUI the size-header, type-header & encoding-header
	local messageRange = tvb( messageStart, msgDetails.msgSize )
	local messageTree = tree:add( dptProto, messageRange )

	messageTree:add( dptProto.fields.sizeHdr, msgSizeRange )
	local typeNode = messageTree:add( dptProto.fields.typeHdr, msgTypeRange )
	local messageTypeName = MessageType.nameByID( msgDetails.msgType )
	typeNode:append_text( " = " .. messageTypeName )
	local encodingNode = messageTree:add( dptProto.fields.encodingHdr, msgEncodingRange )
	encodingNode:append_text( string.format( " = %s", msgEncodingStr ) )

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
		return dissect_connection( tvb, pinfo, tree )
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

-- Connection negotiation fields
dptProto.fields.connectionMagicNumber = ProtoField.uint8( "diffusion.connection.magicNumber", "Magic number" , base.HEX )
dptProto.fields.connectionProtoNumber = ProtoField.uint8( "diffusion.connection.protoNumber", "Protocol number" )
dptProto.fields.connectionType = ProtoField.uint8( "diffusion.connection.connectionType", "Connection Type", base.HEX )

-- Message fields
dptProto.fields.sizeHdr = ProtoField.uint32( "dptProto.size", "Size" )
dptProto.fields.typeHdr = ProtoField.uint8( "dptProto.type", "Type", base.HEX ) --TODO: scope to include lookup table here
dptProto.fields.encodingHdr = ProtoField.uint8( "dptProto.encoding", "Encoding", base.HEX )
dptProto.fields.headers = ProtoField.string( "dptProto.headers", "Headers" )
dptProto.fields.userHeaders = ProtoField.string( "dptProto.userHeaders", "User headers" )
dptProto.fields.fixedHeaders = ProtoField.string( "dptProto.fixedHeaders", "Fixed headers" )
dptProto.fields.content = ProtoField.string( "dptProto.content", "Content" )


-- Register the dissector
tcp_table = DissectorTable.get( "tcp.port" )
tcp_table:add( 8080, dptProto )
