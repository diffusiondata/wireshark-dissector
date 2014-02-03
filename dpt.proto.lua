
-- Check package is not already loaded
local master = diffusion or {}
if master.proto ~= nil then
	return master.proto
end

local srcHost = diffusion.utilities.srcHost
local dstHost = diffusion.utilities.dstHost
local tcpConnections = diffusion.info.tcpConnections
local nameByID = diffusion.messages.nameByID
local addClientConnectionInformation = diffusion.display.addClientConnectionInformation
local addHeaderInformation = diffusion.display.addHeaderInformation
local addBody = diffusion.display.addBody
local addConnectionHandshake = diffusion.display.addConnectionHandshake
local messageTypeLookup = diffusion.messages.messageTypeLookup

local RD, FD = 1, 2
local LENGTH_LEN = 4 -- LLLL
local HEADER_LEN = 2 + LENGTH_LEN -- LLLLTE, usually
local DIFFUSION_MAGIC_NUMBER = 0x23

local f_tcp_stream  = Field.new("tcp.stream")
local f_tcp_srcport = Field.new("tcp.srcport")
local f_frame_number = Field.new("frame.number")

local dptProto = Proto( "DPT", "Diffusion Protocol over TCP")

-- Dissect the connection negotiation messages
local function dissectConnection( tvb, pinfo )
	local offset = 0

	-- Is this a client or server packet?
	local tcpStream, host, port = f_tcp_stream().value, srcHost(), f_tcp_srcport().value

	local client = tcpConnections[tcpStream].client
	local server = tcpConnections[tcpStream].server
	local isClient = client:matches( host, port )

	-- Get the magic number 
	local magicNumberRange = tvb( offset, 1 )
	local magicNumber = magicNumberRange:uint()
	offset = offset +1
	
	-- get the protocol version number
	local protoVerRange = tvb( offset, 1 )
	client.protoVersion = protoVerRange:uint()
	offset = offset +1

	if isClient then
		pinfo.cols.info = string.format( "Connection request" )

		-- the 1 byte connection type
		local connectionTypeRange = tvb( offset, 1 )
		client.connectionType = connectionTypeRange:uint()
		offset = offset +1

		-- the 1 byte capabilities value
		local capabilitiesRange = tvb( offset, 1 )
		client.capabilities = capabilitiesRange:uint()
		offset = offset +1

		local creds, topicset
		-- TODO: load credentials <RD> data <MD>
		local range = tvb( offset )
		local rdBreak = range:bytes():index( RD )
		if rdBreak >= 0 then
			-- Mark up the creds - if there are any
			local credsRange = range(0, rdBreak )
			local credsString = credsRange:string():toRecordString()
			if credsRange:len() > 0 then
				creds = { range = credsRange, string = credsString }
			end

			-- Mark up the login topicset - if there are any
			local topicsetRange = range( rdBreak +1, ( range:len() -2 ) -rdBreak ) -- fiddly handling of trailing null character
			if topicsetRange:len() > 0 then
				topicset = topicsetRange
			end

		end

		return { request = true, magicNumberRange = magicNumberRange,
			protoVerRange = protoVerRange, connectionTypeRange = connectionTypeRange,
			capabilitiesRange = capabilitiesRange, creds = creds, topicsetRange = topicset }

	else
		-- Is a server response
		pinfo.cols.info = string.format( "Connection response" )
		
		local connectionResponseRange = tvb( offset, 1 )
		local connectionResponse = connectionResponseRange:uint()
		offset = offset +1

		-- The size field
		local messageLengthSizeRange = tvb( offset, 1 )
		local messageLengthSize = messageLengthSizeRange:uint() 
		offset = offset +1

		-- the client ID (the rest of this)
		local clientIDRange = tvb( offset, (tvb:len() -1) -offset )  -- fiddly handling of trailing null character
		local clientID = clientIDRange:string()

		client.clientId = clientIDRange:string()

		return { request = false, magicNumberRange = magicNumberRange,
			protoVerRange = protoVerRange, connectionResponseRange = connectionResponseRange,
			messageLengthSizeRange = messageLengthSizeRange, clientIDRange = clientIDRange }
	end

	--TODO: dissect this as a client or as a server packet
end

-- Process an individual DPT message
local function processMessage( tvb, pinfo, tree, offset ) 
	local msgDetails = {}

	local tcpStream = f_tcp_stream().value -- get the artificial 'tcp stream' number
	local conn = tcpConnections[tcpStream]
	local client
	if conn ~= nil then
		client = conn.client
	end

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
	local messageTypeName = nameByID( msgDetails.msgType )
	typeNode:append_text( " = " .. messageTypeName )
	messageTree:add( dptProto.fields.encodingHdr, msgEncodingRange )

	addClientConnectionInformation( messageTree, tvb, client, host, port )

	-- The content range
	local contentSize = msgDetails.msgSize - HEADER_LEN
	local contentRange = tvb( offset, contentSize )
	local contentNode = messageTree:add( dptProto.fields.content, contentRange, string.format( "%d bytes", contentSize ) )

	offset = offset + contentSize
	local messageType = messageTypeLookup(msgDetails.msgType)

	-- The headers & body -- find the 1st RD in the content
	local headerBreak = contentRange:bytes():index( RD )
	if headerBreak >= 0 then
		local headerRange = contentRange:range( 0, headerBreak )
		local headerNode = contentNode:add( dptProto.fields.headers, headerRange, string.format( "%d bytes", headerBreak ) )

		-- Pass the header-node to the MessageType for further processing
		local info = messageType:markupHeaders( headerNode, headerRange )
		addHeaderInformation( headerNode, info )

		if headerBreak +1 <= (contentRange:len() -1) then
			-- Only markup up the body if there is one (there needn't be)
			local bodyRange = contentRange:range( headerBreak +1 )

			local records = messageType:markupBody( msgDetails, contentNode, bodyRange )
			addBody( contentNode , records )
		end
	end
	
	-- Set the Info column of the tabular display -- NB: this must be called last
	pinfo.cols.info = messageType:getDescription()

	return offset
end

function dptProto.init()
	info( "dptProto.init()" )
end

function dptProto.dissector( tvb, pinfo, tree )

	-- Set the tabular display
	pinfo.cols.protocol = dptProto.name

	-- Is this a connection negotiation?
	local firstByte = tvb( 0, 1 ):uint()
	if( firstByte == DIFFUSION_MAGIC_NUMBER ) then
		-- process & skip over it, if it is.
		local handshake = dissectConnection( tvb, pinfo )
		addConnectionHandshake( tree, tvb(), pinfo, handshake )
		return {}
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
	[0x07] = "Supports encrypted, compressed and base 64 encoded data messages"
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

-- Export package
master.proto = {
	dptProto = dptProto
}
diffusion = master
return master.proto

