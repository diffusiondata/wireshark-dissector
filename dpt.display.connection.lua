
-- Display connection package
-- This package adds information about connections to the dissection tree that is displayed in Wireshark. 

-- Package header
local master = diffusion or {}
if master.displayConnection ~= nil then
	return master.displayConnection
end

-- Import from other packages
local dptProto = diffusion.proto.dptProto

-- Attach the connection request information to the dissection tree
local function addConnectionRequest( tree , fullRange, pinfo, request )
	local messageTree = tree:add( dptProto, fullRange )
	if request.magicNumberRange ~= nil then
		messageTree:add( dptProto.fields.connectionMagicNumber, request.magicNumberRange )
	end
	if request.protoVerRange ~= nil then
		messageTree:add( dptProto.fields.connectionProtoNumber, request.protoVerRange )
	end
	if request.wsProtoVersion ~= nil then
		messageTree:add( dptProto.fields.wsConnectionProtoNumber, request.wsProtoVersion )
	end
	if request.connectionTypeRange ~= nil then
		messageTree:add( dptProto.fields.connectionType, request.connectionTypeRange )
	end
	if request.wsConnectionType ~= nil then
		messageTree:add( dptProto.fields.wsConnectionType, request.wsConnectionType )
	end
	if request.capabilitiesRange ~= nil then
		messageTree:add( dptProto.fields.capabilities, request.capabilitiesRange )
	end
	if request.capabilities ~= nil then
		messageTree:add( dptProto.fields.capabilities, fullRange( 0, 0 ), request.capabilities )
	end
	if request.creds ~= nil then
		messageTree:add( dptProto.fields.loginCreds, request.creds.range, request.creds.string )
	end
	if request.wsPrincipal ~= nil then
		messageTree:add( dptProto.fields.wsPrincipal, request.wsPrincipal )
	end
	if request.wsCredentials ~= nil then
		messageTree:add( dptProto.fields.wsCredentials, request.wsCredentials )
	end
	if request.topicsetRange ~= nil then
		messageTree:add( dptProto.fields.loginTopics, request.topicsetRange )
	end

	pinfo.cols.info:clear_fence()
	if request.sessionTokenRange ~= nil then
		messageTree:add( dptProto.fields.sessionToken, request.sessionTokenRange )
		pinfo.cols.info = "DPT Reconnection request"
	elseif request.clientIdRange ~= nil then
		messageTree:add( dptProto.fields.clientID, request.clientIdRange )
		pinfo.cols.info = "DPT Reconnection request"
	else
		pinfo.cols.info = "DPT Connection request"
	end
	pinfo.cols.info:fence()
end

-- Attach the connection response information to the dissection tree
-- Any information present is added to the dissection tree and no information is required
local function addConnectionResponse( tree , fullRange, pinfo, response )
	pinfo.cols.info:clear_fence()
	pinfo.cols.info = "DPT Connection response"
	pinfo.cols.info:fence()

	-- Add the Diffusion protocol element to the tree for the packet
	local messageTree = tree:add( dptProto, fullRange )

	-- Add the magic number
	if response.magicNumberRange ~= nil then
		messageTree:add( dptProto.fields.connectionMagicNumber, response.magicNumberRange )
	end

	-- Add the protocol version when encoded as a byte
	if response.protoVerRange ~= nil then
		messageTree:add( dptProto.fields.connectionProtoNumber, response.protoVerRange )
	end

	-- Add the protocol version when encoded as a char
	if response.protoVerCharRange ~= nil then
		messageTree:add(
			dptProto.fields.connectionProtoNumber,
			response.protoVerCharRange,
			tonumber( response.protoVerCharRange:string() )
		)
	end

	-- Add the response range
	if response.connectionResponseRange ~= nil then
		messageTree:add( dptProto.fields.connectionResponse, response.connectionResponseRange )
	end

	-- Add the connection response range when a string
	if response.connectionResponseStringRange ~= nil then
		messageTree:add(
			dptProto.fields.connectionResponse,
			response.connectionResponseStringRange,
			tonumber(response.connectionResponseStringRange:string())
		)
	end

	-- Add the message length
	if response.messageLengthSizeRange ~= nil then
		messageTree:add( dptProto.fields.messageLengthSize, response.messageLengthSizeRange )
	end

	-- Add the client ID when encoded as a string
	if response.clientIDRange ~= nil then
		messageTree:add( dptProto.fields.clientID, response.clientIDRange )
	end

	-- Add the session ID when encoded as two longs
	if response.sessionId ~= nil then
		messageTree:add(
			dptProto.fields.sessionId,
			response.sessionId.range,
			string.format(
				"%s-%s",
				string.upper( response.sessionId.serverIdentity:tohex() ),
				string.upper( response.sessionId.clientIdentity:tohex() )
			)
		)
	end

	-- Add the session token
	if response.sessionTokenRange ~= nil then
		messageTree:add( dptProto.fields.sessionToken, response.sessionTokenRange )
	end

	-- Add the connection ping period
	if response.pingPeriodRange ~= nil then
		messageTree:add( dptProto.fields.pingPeriod, response.pingPeriodRange )
	end
end

-- Attach the connection handshake information to the dissection tree
local function addConnectionHandshake( tree , fullRange, pinfo, handshake )
	if handshake.request then
		addConnectionRequest( tree, fullRange, pinfo, handshake )
	else
		addConnectionResponse( tree, fullRange, pinfo, handshake )
	end
end

-- Add known information about the connection to other messages
local function addClientConnectionInformation( tree, tvb, client, srcHost, srcPort )
	if client ~= nil then
		local connectionNode = tree:add( dptProto.fields.connection )

		connectionNode:add( dptProto.fields.clientID, tvb(0,0), client.clientId ):set_generated()
		connectionNode:add( dptProto.fields.connectionProtoNumber , tvb(0,0), client.protoVersion ):set_generated()
		if client.connectionType ~= nil then
			connectionNode:add( dptProto.fields.connectionType, tvb(0,0), client.connectionType ):set_generated()
		end
		if client.wsConnectionType ~= nil then
			connectionNode:add( dptProto.fields.wsConnectionType, tvb(0,0), client.wsConnectionType ):set_generated()
		end
		if client.capabilities ~= nil then
			connectionNode:add( dptProto.fields.capabilities, tvb(0,0), client.capabilities ):set_generated()
		end

		-- Indicate direction of message
		if client:matches( srcHost, srcPort ) then
			connectionNode:add( dptProto.fields.direction, tvb(0,0), "Client to Server" ):set_generated()
		else
			connectionNode:add( dptProto.fields.direction, tvb(0,0), "Server to Client" ):set_generated()
		end
	else
		-- Handle missing information
		tree:add( dptProto.fields.connection, tvb(0,0), "Connection unknown, partial capture" )
	end
end

-- Package footer
master.displayConnection = {
	addConnectionHandshake = addConnectionHandshake,
	addClientConnectionInformation = addClientConnectionInformation
}
diffusion = master
return master.displayConnection