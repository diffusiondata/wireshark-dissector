
-- Dissector package
-- This package attaches the dissector, parsing and display behaviour to the protocol. Unlike other packages this
-- modifies previously created objects.

-- Package header
local master = diffusion or {}
if master.dissector ~= nil then
	return master.dissector
end

local RD, FD = diffusion.utilities.RD, diffusion.utilities.FD

local f_src_host = diffusion.utilities.f_src_host
local f_dst_host = diffusion.utilities.f_dst_host
local f_src_port = diffusion.utilities.f_src_port
local f_tcp_stream  = diffusion.utilities.f_tcp_stream
local f_http_response_code = diffusion.utilities.f_http_response_code
local f_http_connection = diffusion.utilities.f_http_connection
local f_http_upgrade = diffusion.utilities.f_http_upgrade
local f_http_uri = diffusion.utilities.f_http_uri

local tcpConnections = diffusion.info.tcpConnections

local nameByID = diffusion.messages.nameByID
local messageTypeLookup = diffusion.messages.messageTypeLookup

local dptProto = diffusion.proto.dptProto

local parseAsV4ServiceMessage = diffusion.parseService.parseAsV4ServiceMessage
local parseConnectionRequest = diffusion.parse.parseConnectionRequest
local parseConnectionResponse = diffusion.parse.parseConnectionResponse
local parseWSConnectionRequest = diffusion.parse.parseWSConnectionRequest

local addClientConnectionInformation = diffusion.display.addClientConnectionInformation
local addHeaderInformation = diffusion.display.addHeaderInformation
local addBody = diffusion.display.addBody
local addConnectionHandshake = diffusion.display.addConnectionHandshake
local addServiceInformation = diffusion.display.addServiceInformation
local addDescription = diffusion.display.addDescription

local SERVICE_TOPIC = diffusion.v5.SERVICE_TOPIC

local LENGTH_LEN = 4 -- LLLL
local HEADER_LEN = 2 + LENGTH_LEN -- LLLLTE, usually
local DIFFUSION_MAGIC_NUMBER = 0x23

local tcp_dissector_table = DissectorTable.get("tcp.port")
local http_dissector = tcp_dissector_table:get_dissector(80)

local DPT_TYPE = "DPT_TYPE"
local DPWS_TYPE = "DPWS_TYPE"
local OTHER_TYPE = "OTHER_TYPE"

-- Dissect the connection negotiation messages
local function dissectConnection( tvb, pinfo )
	-- Is this a client or server packet?
	local tcpStream, host, port = f_tcp_stream(), f_src_host(), f_src_port()

	local client = tcpConnections[tcpStream].client
	local server = tcpConnections[tcpStream].server
	local isClient = client:matches( host, port )

	if isClient then
		return parseConnectionRequest( tvb, client )
	else
		return parseConnectionResponse( tvb, client )
	end
end

local function tryDissectWSConnection( tvb, pinfo )
	local uri = f_http_uri()
	if uri ~= nil then
		if uri:startsWith("/diffusion") then
			return parseWSConnectionRequest( tvb, client )
		end
	end

	return nil
end

local function tryDissectWSConnectionResponse( tvb, pinfo )
	return {
		request = false
	}
end

-- Process an individual DPT message
local function processMessage( tvb, pinfo, tree, offset ) 
	local msgDetails = {}

	local tcpStream = f_tcp_stream() -- get the artificial 'tcp stream' number
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

	addClientConnectionInformation( messageTree, tvb, client, f_src_host(), f_src_port() )

	-- The content range
	local contentSize = msgDetails.msgSize - HEADER_LEN
	local contentRange = tvb( offset, contentSize )

	offset = offset + contentSize
	local messageType = messageTypeLookup(msgDetails.msgType)

	local headerInfo, serviceInfo, records
	-- The headers & body -- find the 1st RD in the content
	local headerBreak = contentRange:bytes():index( RD )
	if headerBreak >= 0 then
		local headerRange = contentRange:range( 0, headerBreak )

		-- Pass the header-node to the MessageType for further processing
		headerInfo = messageType:markupHeaders( headerRange )

		if headerBreak + 1 <= (contentRange:len() -1) then
			-- Only markup up the body if there is one (there needn't be)
			local bodyRange = contentRange:range( headerBreak +1 )

			if headerInfo.topic ~= nil and headerInfo.topic.topic ~= nil and headerInfo.topic.topic.string == SERVICE_TOPIC then
				serviceInfo = parseAsV4ServiceMessage( bodyRange )
			end

			records = messageType:markupBody( msgDetails, bodyRange )
			if serviceInfo ~= nil then
				addServiceInformation( messageTree, serviceInfo, records )
			end
		end

		if serviceInfo == nil then
			local contentNode = messageTree:add( dptProto.fields.content, contentRange, string.format( "%d bytes", contentSize ) )
			local headerNode = contentNode:add( dptProto.fields.headers, headerRange, string.format( "%d bytes", headerBreak ) )
			addHeaderInformation( headerNode, headerInfo )
			if records ~= nil then
				addBody( contentNode , records )
			end
		end
	end
	
	-- Set the Info column of the tabular display -- NB: this must be called last
	addDescription( pinfo, messageType, headerInfo, serviceInfo )

	return offset
end

function dptProto.init()
	info( "dptProto.init()" )
end

function dptProto.dissector( tvb, pinfo, tree )

	local streamNumber = f_tcp_stream()

	-- Is this a connection negotiation?
	-- Dissect connection and mark stream as DPT
	local firstByte = tvb( 0, 1 ):uint()
	if firstByte == DIFFUSION_MAGIC_NUMBER then
		tcpConnections[streamNumber].type = DPT_TYPE

		-- Set the tabular display
		pinfo.cols.protocol = dptProto.name

		-- process & skip over it, if it is.
		local handshake = dissectConnection( tvb, pinfo )
		addConnectionHandshake( tree, tvb(), pinfo, handshake )
		return {}
	end

	http_dissector:call( tvb, pinfo, tree)

	local connection = f_http_connection()
	local upgrade = f_http_upgrade()

	if connection == "Upgrade" and upgrade == "WebSocket" then
		local handshake = tryDissectWSConnection( tvb, pinfo )
		if handshake ~= nil then
			pinfo.cols.info:clear_fence()
			pinfo.cols.protocol = "DP-WS"
			tcpConnections[streamNumber].type = DPWS_TYPE
			addConnectionHandshake( tree, tvb(), pinfo, handshake )
			return {}
		end
	end

	if tcpConnections[streamNumber].type == DPT_TYPE then
		-- Set the tabular display
		pinfo.cols.protocol = dptProto.name

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

	if tcpConnections[streamNumber].type == DPWS_TYPE then
		pinfo.cols.info:clear_fence()

		pinfo.cols.protocol = "DP-WS"

		local response = f_http_response_code()
		if response == 101 then
			local handshake = tryDissectWSConnectionResponse( tvb, pinfo)
			addConnectionHandshake( tree, tvb(), pinfo, handshake )
		end
	end

	if tcpConnections[streamNumber].type == nil then
		--pinfo.cols.protocol = "OTHER"
	end

end

-- Package footer
master.dissector = {}
diffusion = master
return master.dissector
