
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parse ~= nil then
	return master.parse
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local f_time_epoch = diffusion.utilities.f_time_epoch
local f_src_port = diffusion.utilities.f_src_port
local f_src_host = diffusion.utilities.f_src_host
local f_http_uri = diffusion.utilities.f_http_uri
local dump = diffusion.utilities.dump
local index = diffusion.utilities.index
local aliasTable = diffusion.info.aliasTable
local tcpConnections = diffusion.info.tcpConnections
local serviceMessageTable = diffusion.info.serviceMessageTable
local lookupClientTypeByChar = diffusion.parseCommon.lookupClientTypeByChar
local parseSessionId = diffusion.parseCommon.parseSessionId
local v5 = diffusion.v5

local RD, FD = diffusion.utilities.RD, diffusion.utilities.FD

-- Parse the first header as a topic
-- Takes the header range
-- Assumes there will be more than one header
-- Adds the topic to the aliasTable if an alias is present
-- Retrieves the topic from the aliasTable if there is only an alias
-- Returns the remaining header range, the topic range and string as a pair and the alias topic and string as a pair
-- The remaining header range will be nil if there are no more headers
-- The alias.range will be nil if there is no alias present in the header
local function parseTopicHeader( headerRange )
	local topicEndIndex = index( headerRange:bytes(), FD )
	local topicExpressionRange

	if topicEndIndex > -1 then
		topicExpressionRange = headerRange:range( 0, topicEndIndex )
		headerRange = headerRange:range( topicEndIndex + 1 )
	else
		topicExpressionRange = headerRange
		headerRange = nil
	end

	local delimIndex = index( topicExpressionRange:bytes(), 0x21 )
	local tcpStream = f_tcp_stream()
	local topicObject
	local aliasObject
	if delimIndex == 0 then
		local aliasRange = topicExpressionRange
		local alias = aliasRange:string();

		local topic = aliasTable:getAlias( tcpStream, alias )

		if topic == nil then
			aliasObject = { range = aliasRange, string = alias }
			topicObject = { range = aliasRange, string = "Unknown topic alias (ITL not captured)", resolved = false }
		else
			aliasObject = { range = aliasRange, string = alias }
			topicObject = { range = aliasRange, string = topic, resolved = true }
		end
	elseif delimIndex > -1 then
		local topicRange = topicExpressionRange:range( 0, delimIndex )
		local aliasRange = topicExpressionRange:range( delimIndex )

		local topic = topicRange:string()
		local alias = aliasRange:string()

		aliasTable:setAlias( tcpStream, alias, topic )

		aliasObject = { range = aliasRange, string = alias }
		topicObject = { range = topicRange, string = topic, resolved = false }
	else
		local topicRange = topicExpressionRange
		local topic = topicRange:string()
		topicObject = { range = topicRange, string = topic, resolved = false }
		aliasObject = {}
	end

	return headerRange, { topic = topicObject, alias = aliasObject }
end

local function parseRecordFields( recordRange )
	local bytes = recordRange:bytes()
	local bytesLen = bytes:len()
	local fs = {}

	local fieldStart = 0
	local pos = 0
	local idx = 1

	-- On each field delimiter add the previous field to result
	while pos < bytesLen do
		local byte = bytes:get_index(pos)

		if byte == FD then
			local fieldRange = recordRange:range( fieldStart, pos - fieldStart )
			fs[idx] = { range = fieldRange, string = fieldRange:string() }
			idx = idx + 1
			pos = pos + 1
			fieldStart = pos
		else
			pos = pos + 1
		end

	end

	-- Fields are delimited so treat the end as another delimiter
	-- Special handling is needed to get an empty range at the end for a trailing empty field
	if pos - fieldStart == 0 then
		fs[idx] = { range = recordRange:range( fieldStart - 1, 0 ), string = "" }
	else
		local fieldRange = recordRange:range( fieldStart )
		fs[idx] = { range = fieldRange, string = fieldRange:string() }
	end

	fs.num = idx
	return fs
end

local function parseField( headerRange )
	local fieldEndIndex = index( headerRange:bytes(), FD )
	if fieldEndIndex > -1 then
		return headerRange:range( 0, fieldEndIndex ), headerRange:range( fieldEndIndex + 1 )
	else
		return headerRange, nil
	end
end

local function parseAckId( headerRange )
	local ackIdRange
	ackIdRange, headerRange = parseField( headerRange )
	return { range = ackIdRange, string = ackIdRange:string() }, headerRange
end

local function parseV5ReconnectionRequest( tvb, client, result )

	-- the 1 byte connection type
	local connectionTypeRange = tvb( 3, 1 )
	client.connectionType = connectionTypeRange:uint()
	result.connectionTypeRange = connectionTypeRange

	-- the 1 byte capabilities value
	local capabilitiesRange = tvb( 4, 1 )
	client.capabilities = capabilitiesRange:uint()
	result.capabilitiesRange = capabilitiesRange

	-- the session token
	result.sessionTokenRange = tvb( 5, 24 )

	return result
end

local function parseConnectionRequest( tvb, client )
	-- Get the magic number
	local magicNumberRange = tvb( 0, 1 )
	local magicNumber = magicNumberRange:uint()

	-- get the protocol version number
	local protoVerRange = tvb( 1, 1 )
	client.protoVersion = protoVerRange:uint()

	-- if the protocol version is 5 or above and the next byte is 2 then it is a reconnection attempt otherwise the byte
	-- is the connection type
	local connectionTypeRange = tvb( 2, 1 )

	if connectionTypeRange:uint() == 2 then
		return parseV5ReconnectionRequest(
			tvb,
			client,
			{
				request = true,
				magicNumberRange = magicNumberRange,
				protoVerRange = protoVerRange
			}
		)
	end

	-- the 1 byte connection type
	client.connectionType = connectionTypeRange:uint()

	-- the 1 byte capabilities value
	local capabilitiesRange = tvb( 3, 1 )
	client.capabilities = capabilitiesRange:uint()

	local creds, topicset, topicSetOffset, clientIdOffset, clientId
	local range = tvb( 4 )
	local rdBreak = range:bytes():index( RD )

	if rdBreak >= 0 then
		-- Mark up the creds - if there are any
		local credsRange = range(0, rdBreak )
		local credsString = credsRange:string():toRecordString()
		if credsRange:len() > 0 then
			creds = { range = credsRange, string = credsString }
		end
		topicSetOffset = rdBreak + 1
	else
		topicSetOffset = 0
	end

	local fdBreak = index( range( topicSetOffset ):bytes(), FD )
	if fdBreak >= 0 then
		if topicSetOffset < range:len() then
			-- Mark up the login topicset - if there are any
			local topicsetRange = range( topicSetOffset, fdBreak )
			if topicsetRange:len() > 0 then
				topicset = topicsetRange
			end
			clientIdOffset = topicSetOffset + fdBreak + 1
		else
			clientIdOffset = topicSetOffset
		end

		if clientIdOffset < range:len() then
			local clientIdRange = range( clientIdOffset, (range:len() - 1) - (clientIdOffset) )
			if clientIdRange:len() > 0 then
				clientId = clientIdRange
			end
		end
	else
		if topicSetOffset < range:len() then
			-- Mark up the login topicset - if there are any
			local topicsetRange = range( topicSetOffset, (range:len() - 1) - (topicSetOffset) )
			if topicsetRange:len() > 0 then
				topicset = topicsetRange
			end
		end
	end

	return { request = true, magicNumberRange = magicNumberRange,
		protoVerRange = protoVerRange, connectionTypeRange = connectionTypeRange,
		capabilitiesRange = capabilitiesRange, creds = creds, topicsetRange = topicset, clientIdRange = clientId }
end

-- Parse V4 connection responses
local function parseV4ConnectionResponse( tvb, client )
	local result = {
		request = false
	}

	-- Get the magic number
	result.magicNumberRange = tvb( 0, 1 )

	-- get the protocol version number
	result.protoVerRange = tvb( 1, 1 )
	client.protoVersion = result.protoVerRange:uint()

	result.connectionResponseRange = tvb( 2, 1 )

	-- The size field
	result.messageLengthSizeRange = tvb( 3, 1 )

	-- the client ID (the rest of this)
	result.clientIDRange = tvb( 4, tvb:len() - 5 )  -- fiddly handling of trailing null character
	client.clientId = result.clientIDRange:string()

	return result
end

-- Parse V5 and later connection responses
local function parseV5ConnectionResponse( tvb, client )
	local result = {
		request = false
	}

	-- Get the magic number
	result.magicNumberRange = tvb( 0, 1 )

	-- get the protocol version number
	result.protoVerRange = tvb( 1, 1 )
	client.protoVersion = result.protoVerRange:uint()

	-- Parse response
	result.connectionResponseRange = tvb( 2, 1 )
	local connectionResponse = result.connectionResponseRange:uint()

	if connectionResponse == 100 or connectionResponse == 105 then
		-- Parse Session ID
		result.sessionId = parseSessionId( tvb( 3 ) )
		client.clientId = result.sessionId.clientId

		-- Parse session token
		result.sessionTokenRange = tvb( 19, 24 )
	end

	if client.protoVersion > 6 then
		result.pingPeriodRange = tvb ( 43, 8 )
	end

	return result
end

-- Identify how to parse the DPT connection response and call the correct parser
local function parseConnectionResponse( tvb, client )
	-- Check the magic number
	local magicNumber = tvb( 0, 1 ):uint()
	if magicNumber ~= 0x23 then
		info( string.format( "Unknown first byte %x", magicNumber) )
		return nil
	end

	-- Check the protocol version number
	local protoVersion = tvb( 1, 1 ):uint()
	if protoVersion > 4 then
		return parseV5ConnectionResponse( tvb, client )
	else
		return parseV4ConnectionResponse( tvb, client )
	end
end

local function findUriParameters( uriRange )
	if uriRange( 0, 11 ):string() == "/diffusion?" then
		return uriRange( 11 )
	end

	if uriRange( 0, 12 ):string() == "/diffusion/?" then
		return uriRange( 12 )
	end

	return nil
end

local function uriToQueryParameters( uriRange )
	local parameterTable = {}

	-- Check length
	if (uriRange:len() < 12) then
		return nil
	end

	-- Check start
	local remainingParameters = findUriParameters( uriRange )
	if remainingParameters == nil then
		return nil
	end

	while remainingParameters:len() > 0 do
		-- Get the parameter name
		local nameEnd = 0
		while nameEnd < remainingParameters:len() and remainingParameters( nameEnd, 1 ):string() ~= "=" do
			nameEnd = nameEnd + 1
		end

		-- Get the parameter value
		local valueEnd = nameEnd
		while valueEnd < remainingParameters:len() and remainingParameters( valueEnd, 1 ):string() ~= "&" do
			valueEnd = valueEnd + 1
		end

		local name = remainingParameters( 0, nameEnd )
		local value = remainingParameters( nameEnd + 1 , valueEnd - nameEnd - 1 )

		parameterTable[name:string()] = value

		if valueEnd == remainingParameters:len() then
			remainingParameters = remainingParameters( 0, 0 )
		else
			remainingParameters = remainingParameters( valueEnd + 1 )
		end
	end

	return parameterTable
end

local function parseWSConnectionRequest( tvb, client )
	local uriRange = f_http_uri()
	local parameters = uriToQueryParameters( uriRange )
	if parameters == nil then
		return nil
	end

	local clientType = lookupClientTypeByChar( parameters["ty"]:string() )
	client.wsConnectionType = clientType
	client.capabilities = tonumber( parameters["ca"]:string() )

	return {
		request = true,
		wsProtoVersion = parameters["v"],
		wsConnectionType = {
			range = parameters["ty"],
			string = clientType
		},
		capabilities = parameters["ca"],
		wsPrincipal = parameters["username"],
		wsCredentials = parameters["password"],
		reconnectionTimeout = parameters["r"],
	}
end

-- Parse V4 over WS connection responses
local function parseV4WSConnectionResponse( tvb, client, result )
	local result = {
		request = false
	}
	-- get the protocol version number
	result.protoVerCharRange = tvb( 0, 1 )
	client.protoVersion = tonumber( result.protoVerCharRange:string() )

	result.connectionResponseStringRange = tvb( 2, 3 )
	local connectionResponse = result.connectionResponseStringRange:string()

	if connectionResponse == "100" or connectionResponse == "105" then
		result.clientIDRange = tvb( 6 )
		result.clientID = result.clientIDRange:string()
		client.clientId = result.clientID
	end

	return result
end

-- Identify how to parse the WS connection response and call the correct parser
local function parseWSConnectionResponse( tvb, client )
	-- Get the first byte
	local firstByte = tvb( 0, 1 ):uint()
	if firstByte == 0x34 then -- ASCII 4, classic WS protocol
		return parseV4WSConnectionResponse( tvb, client )
	elseif firstByte == 0x23 then -- Magic byte, DPT-like connection
		local protoVersion = tvb( 1, 1 ):uint()
		if protoVersion > 4 then
			return parseV5ConnectionResponse( tvb, client )
		else
			return nil
		end
	else
		info( string.format( "Unknown first byte %x", firstByte) )
		return nil
	end
end

local function decodeMessageType( byte )
	return bit32.band( byte, 0x3f )
end

-- Package footer
master.parse = {
	parseTopicHeader = parseTopicHeader,
	parseRecordFields = parseRecordFields,
	parseField = parseField,
	parseAckId = parseAckId,
	parseConnectionRequest = parseConnectionRequest,
	parseConnectionResponse = parseConnectionResponse,
	parseWSConnectionRequest = parseWSConnectionRequest,
	parseWSConnectionResponse = parseWSConnectionResponse,
	decodeMessageType = decodeMessageType
}
diffusion = master
return master.parse
