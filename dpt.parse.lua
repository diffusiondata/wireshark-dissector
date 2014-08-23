
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parse ~= nil then
	return master.parse
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local f_time_epoch = diffusion.utilities.f_time_epoch
local srcPort = diffusion.utilities.srcPort
local srcHost = diffusion.utilities.srcHost
local aliasTable = diffusion.info.aliasTable
local topicIdTable = diffusion.info.topicIdTable
local tcpConnections = diffusion.info.tcpConnections
local v5 = diffusion.v5

local RD, FD = 1, 2

-- Stores information about specific service requests
local ServiceMessageTable = {}
function ServiceMessageTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end

-- Add information about a service request
function ServiceMessageTable:addRequest( tcpStream, requestSrc, conversation, time )
	local serviceConversationStream = self[tcpStream] or {}
	local serviceConversation = serviceConversationStream[requestSrc] or {}
	serviceConversation[conversation] = {}
	serviceConversation[conversation].time = time
	serviceConversationStream[requestSrc] = serviceConversation
	self[tcpStream] = serviceConversationStream
end

-- Get the time of a service request
function ServiceMessageTable:getRequestTime( tcpStream, requestSrc, conversation )
	local res = self[tcpStream][requestSrc][conversation]
	return res.time
end

local serviceMessageTable = ServiceMessageTable:new()

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
		local byte = range:range( idx, 1 ):uint()
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

local function parseControlRegistrationRequest( range )
	local serviceIdRange, remaining, serviceId = varint( range )
	local controlGroup = lengthPrefixedString( remaining )
	return { serviceId = { range = serviceIdRange, int = serviceId }, controlGroup = controlGroup }, controlGroup.remaining
end

local function parseAuthenticationControlRegistrationRequest( range )
	local result, remaining = parseControlRegistrationRequest( range )
	local handlerName = lengthPrefixedString( remaining )
	return { controlRegInfo = result, handlerName = handlerName }
end

local function parseTopicControlRegistrationRequest( range )
	local result, remaining = parseControlRegistrationRequest( range )
	local topicPath = lengthPrefixedString( remaining )
	return { controlRegInfo = result, handlerTopicPath = topicPath }
end

local function parseTopicSourceRegistrationRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	return { converstationId = {range = cIdRange, int = cId}, topicPath = topicPath }
end

local function parseTopicUpdateRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	-- TODO: Update parsing
	return { converstationId = {range = cIdRange, int = cId}, topicPath = topicPath }
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
	local tcpStream = f_tcp_stream()
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
	local tcpStream = f_tcp_stream()
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

		local tcpStream = f_tcp_stream()
		if mode == v5.MODE_REQUEST then
			local session = tcpConnections[tcpStream]
			local isClient = session.client:matches( srcHost(), srcPort() )
			if isClient then
				-- Request is from the client so the client created the conversation Id
				serviceMessageTable:addRequest( tcpStream, session.client, conversation, f_time_epoch() )
			else
				-- Request is from the server so the server created the conversation Id
				serviceMessageTable:addRequest( tcpStream, session.server, conversation, f_time_epoch() )
			end

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
			elseif service == v5.SERVICE_AUTHENTICATION_CONTROL_REGISTRATION then
				local info = parseAuthenticationControlRegistrationRequest( serviceBodyRange )
				result.controlRegInfo = info.controlRegInfo
				result.handlerName = info.handlerName
			elseif service == v5.SERVICE_TOPIC_CONTROL_REGISTRATION then
				local info = parseTopicControlRegistrationRequest( serviceBodyRange )
				result.controlRegInfo = info.controlRegInfo
				result.handlerTopicPath = info.handlerTopicPath
			elseif service == v5.SERVICE_SERVER_CONTROL_REGISTRATION then
				local info = parseControlRegistrationRequest( serviceBodyRange )
				result.controlRegInfo = info
			elseif service == v5.SERVICE_TOPIC_SOURCE_REGISTRATION then
				local info = parseTopicSourceRegistrationRequest( serviceBodyRange )
				result.topicSourceInfo = info
			elseif service == v5.SERVICE_UPDATE_SOURCE_UPDATE then
				local info = parseTopicUpdateRequest( serviceBodyRange )
				result.updateInfo = info
			end
		elseif  mode == v5.MODE_RESPONSE then
			local reqTime
			local session = tcpConnections[tcpStream]
			local isClient = session.client:matches( srcHost(), srcPort() )
			if isClient then
				-- Response is from the client so the server created the conversation Id
				reqTime = serviceMessageTable:getRequestTime( tcpStream, session.server, conversation )
			else
				-- Response is from the server so the client created the conversation Id
				reqTime = serviceMessageTable:getRequestTime( tcpStream, session.client, conversation )
			end
			result.responseTime = tostring( f_time_epoch() - reqTime )
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
	local fieldBase = 0
	local rangeString = recordRange:string()
	local fields = rangeString:split( string.char( FD ) )
	local fs = {}

	local idx = 1
	-- Break open into records & then fields
	-- There is some duplication going on to get the field ranges
	for i, field in ipairs(fields) do

		local fieldRange = recordRange:range( fieldBase, #field )
		fs[idx] = { range = fieldRange, string = fieldRange:string() }
		idx = idx + 1

		-- Find any empty fields and the starting point of the next non-empty field
		fieldBase = fieldBase + #field + 1
		while recordRange:len() > fieldBase and recordRange:range( fieldBase, 1 ):int() == FD do
			fs[idx] = { range = recordRange:range( fieldBase, 0 ), string = "" }
			idx = idx + 1
			fieldBase = fieldBase + 1
		end

	end
	fs.num = idx - 1
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
