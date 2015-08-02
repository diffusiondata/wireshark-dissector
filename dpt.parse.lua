
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
local aliasTable = diffusion.info.aliasTable
local topicIdTable = diffusion.info.topicIdTable
local tcpConnections = diffusion.info.tcpConnections
local serviceMessageTable = diffusion.info.serviceMessageTable
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
	local fieldEndIndex = headerRange:bytes():index( FD )
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

local function parseConnectionRequest( tvb, client )
	-- Get the magic number 
	local magicNumberRange = tvb( 0, 1 )
	local magicNumber = magicNumberRange:uint()

	-- get the protocol version number
	local protoVerRange = tvb( 1, 1 )
	client.protoVersion = protoVerRange:uint()

	-- the 1 byte connection type
	local connectionTypeRange = tvb( 2, 1 )
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

	local fdBreak = range( topicSetOffset ):bytes():index( FD )
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

local function parseConnectionResponse( tvb, client )
	-- Get the magic number 
	local magicNumberRange = tvb( 0, 1 )
	local magicNumber = magicNumberRange:uint()

	-- get the protocol version number
	local protoVerRange = tvb( 1, 1 )
	client.protoVersion = protoVerRange:uint()

	-- Is a server response

	local connectionResponseRange = tvb( 2, 1 )
	local connectionResponse = connectionResponseRange:uint()

	-- The size field
	local messageLengthSizeRange = tvb( 3, 1 )
	local messageLengthSize = messageLengthSizeRange:uint() 

-- the client ID (the rest of this)
	local clientIDRange = tvb( 4, tvb:len() - 5 )  -- fiddly handling of trailing null character
	local clientID = clientIDRange:string()

	client.clientId = clientIDRange:string()

	return { request = false, magicNumberRange = magicNumberRange,
		protoVerRange = protoVerRange, connectionResponseRange = connectionResponseRange,
		messageLengthSizeRange = messageLengthSizeRange, clientIDRange = clientIDRange }
end

local function uriToQueryParameters ( uri )
	local parameterTable = {}
	local queryString = string.gsub(uri, "/diffusion%?", "")
	info( queryString )
	-- Foreach '&' separated string split around '=' and store as key value pairs
	info( "Parameters" )
	string.gsub( queryString, "([^&]+)", function( parameterPair )
		local parameterComponents = parameterPair:split("=")
		parameterTable[parameterComponents[1]] = parameterComponents[2]
	end )
	info ( dump(parameterTable) )

	return parameterTable
end

local function parseWSConnectionRequest ( tvb, client )
	local uri = f_http_uri()
	local parameters = uriToQueryParameters( uri )
	return {
		request = true,
		wsProtoVersion = parameters["v"],
		wsConnectionType = parameters["ty"],
		wsCapabilities = parameters["ca"],
		wsPrincipal = parameters["username"],
		wsCredentials = parameters["password"]
	}
end

-- Package footer
master.parse = {
	parseTopicHeader = parseTopicHeader,
	parseRecordFields = parseRecordFields,
	parseField = parseField,
	parseAckId = parseAckId,
	parseConnectionRequest = parseConnectionRequest,
	parseConnectionResponse = parseConnectionResponse,
	parseWSConnectionRequest = parseWSConnectionRequest
}
diffusion = master
return master.parse
