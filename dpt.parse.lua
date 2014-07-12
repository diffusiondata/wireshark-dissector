
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parse ~= nil then
	return master.parse
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local aliasTable = diffusion.info.aliasTable
local topicIdTable = diffusion.info.topicIdTable
local v5 = diffusion.v5

local RD, FD = 1, 2

-- Decode the varint used by command serialiser
-- Takes a range containing the varint
-- Returns: a range containing the varint, a range excluding the varint, the
-- numeric value of the varint
-- TODO: Unit test
local function varint( range )
	local sum = 0
	local idx = 0
	local shift = 0

	if range:len() == 1 then
		local r = range:range( 0, 1 )
		return r, range:range( 0, 0 ), r:uint()
	end

	while idx + 1 < range:len() do
		local byte = range:range( idx, idx + 1 ):uint()
		if byte >= 128 then
			sum = sum + ( shift + byte - 128 )
			idx = idx + 1
			shift = shift + ( 2 ^ idx * 8 )
		else
			sum = sum + ( shift + byte )
			idx = idx + 1
			break
		end
	end
	return range:range( 0, idx ), range:range( idx ), sum
end

local function lengthPrefixedString( range )
	if range ~= nil then
		local lengthRange, rRange, length = varint( range )
		local fullLength = lengthRange:len() + length

		local stringRange = rRange:range( 0, length )
		if rRange:len() > length then
			local remainingRange = rRange:range( length )
			return { range = stringRange, remaining = remainingRange, fullRange = range( 0, fullLength ), string = stringRange:string() }
		else
			return { range = stringRange, fullRange = range( 0, fullLength ), string = stringRange:string() }
		end
	end
end

local function parseAttrubutes( range )
	--TODO: Attribute parsing
end

local function parseSchema( range )
	--TODO: Schema parsing
end

local function parseTopicDetails( detailsRange )
	local any = detailsRange:range( 0, 1 )
	if any:int() == 0 then
		return { range = any, type = { type = 0, range = any } }
	else
		local type = detailsRange:range( 1, 1 )
		local typeRange = detailsRange:range( 0, 2 )
		if detailsRange:range( 2, 1 ):int() == 0 then
			-- Basic
			return { range = detailsRange:range( 0, 3 ), type = { type = type:int(), range = typeRange } }
		else
			-- Schema+
			local schema = parseSchema( detailsRange:range( 3 ) )
			return { range = typeRange, type = { type = type:int(), range = typeRange } }
		end
	end
end

local function parseSubscriptionNotification( range )
	local idRange, remaining, id = varint( range )
	local path = lengthPrefixedString( remaining )
	local topicDetails = parseTopicDetails( path.remaining )
	local tcpStream = f_tcp_stream().value
	topicIdTable:setAlias( tcpStream, id, path.range:string() )
	local topicInfo = {
		range = range,
		id = { range = idRange, int = id },
		path = { range = path.fullRange, string = path.range:string() },
		details = topicDetails
	}
	return topicInfo
end

local function parseUnsubscriptionNotification( range )
	local idRange, remaining, id = varint( range )
	local reasonRange, remaining, reason = varint( remaining )
	local tcpStream = f_tcp_stream().value
	local topicName = topicIdTable:getAlias( tcpStream, id )
	return {
		topic = { name = topicName, range = idRange },
		reason = { reason = reason, range = reasonRange }
	}
end

local function parseStatus( range )
	return { range = range }
end

-- Parse the message as a service request or response
local function parseAsV4ServiceMessage( range )
	if range ~= nil and range:len() >= 2 then
		-- Parse varints
		local serviceRange, modeR, service = varint( range )
		local modeRange, conversationR, mode = varint( modeR )
		local conversationRange, serviceBodyRange, conversation = varint( conversationR )
		-- Get values for service node
		local serviceNodeRange = range

		local result = { range = serviceNodeRange, id = { range = serviceRange, int = service },
			mode = { range = modeRange, int = mode },
			conversation = { range = conversationRange, int = conversation },
			body = serviceBodyRange }

		if mode == v5.MODE_REQUEST then
			if service == v5.SERVICE_FETCH then
				local selector = lengthPrefixedString( serviceBodyRange )
				result.selector = { range = selector.fullRange, string = selector.string }
			elseif service == v5.SERVICE_SUBSCRIBE then
				local selector = lengthPrefixedString( serviceBodyRange )
				result.selector = { range = selector.fullRange, string = selector.string }
			elseif service == v5.SERVICE_UNSUBSCRIBE then
				local selector = lengthPrefixedString( serviceBodyRange )
				result.selector = { range = selector.fullRange, string = selector.string }
			elseif service == v5.SERVICE_ADD_TOPIC then
				local topicName = lengthPrefixedString( serviceBodyRange )
				result.topicName = topicName
			elseif service == v5.SERVICE_REMOVE_TOPICS then
				local selector = lengthPrefixedString( serviceBodyRange )
				result.selector = { range = selector.fullRange, string = selector.string }
			elseif service == v5.SERVICE_SUBSCRIPTION_NOTIFICATION then
				result.topicInfo = parseSubscriptionNotification( serviceBodyRange )
			elseif service == v5.SERVICE_UNSUBSCRIPTION_NOTIFICATION then
				result.topicUnsubscriptionInfo = parseUnsubscriptionNotification( serviceBodyRange )
			end
		elseif  mode == v5.MODE_RESPONSE then
		end

		return result
	else
		return {}
	end
end

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
	local tcpStream = f_tcp_stream().value
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

	local creds, topicset, topicSetOffset
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

	if topicSetOffset < range:len() then
		-- Mark up the login topicset - if there are any
		local topicsetRange = range( topicSetOffset, ( range:len() - 1 ) - topicSetOffset ) -- fiddly handling of trailing null character
		if topicsetRange:len() > 0 then
			topicset = topicsetRange
		end
	end

	return { request = true, magicNumberRange = magicNumberRange,
		protoVerRange = protoVerRange, connectionTypeRange = connectionTypeRange,
		capabilitiesRange = capabilitiesRange, creds = creds, topicsetRange = topicset }
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

-- Package footer
master.parse = {
	parseTopicHeader = parseTopicHeader,
	parseRecordFields = parseRecordFields,
	parseField = parseField,
	parseAckId = parseAckId,
	parseConnectionRequest = parseConnectionRequest,
	parseConnectionResponse = parseConnectionResponse,
	parseAsV4ServiceMessage = parseAsV4ServiceMessage
}
diffusion = master
return master.parse
