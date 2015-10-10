
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parseService ~= nil then
	return master.parseService
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local f_time_epoch = diffusion.utilities.f_time_epoch
local f_src_port = diffusion.utilities.f_src_port
local f_src_host = diffusion.utilities.f_src_host
local topicIdTable = diffusion.info.topicIdTable
local tcpConnections = diffusion.info.tcpConnections
local serviceMessageTable = diffusion.info.serviceMessageTable
local v5 = diffusion.v5
local varint = diffusion.parseCommon.varint
local lengthPrefixedString = diffusion.parseCommon.lengthPrefixedString

local function parseDetailTypeSet( range )
	local numberOfDetailTypes = range:range( 0, 1 ):uint()
	local set = { length = numberOfDetailTypes }
	for i = 0, numberOfDetailTypes - 1 do
		set[i] = range:range( 1 + i, 1 )
	end
	set.range = range:range( 0, numberOfDetailTypes + 1 )
	return set, range:range( numberOfDetailTypes + 1 )
end

local function parseSessionDetailsListenerRegistrationRequest( range )
	local hasDetailTypes = range:range( 0, 1 ):uint()

	if hasDetailTypes == 0 then
		local cIdRange, remaining, cId = varint( range:range( 1 ) )
		return { conversationId = {range = cIdRange, int = cId}, detailTypeSet = { range = range:range( 0, 1 ), length = 0 } }
	else
		local detailTypeSet, remaining = parseDetailTypeSet( range:range( 1 ) )
		local cIdRange, remaining, cId = varint( remaining )
		return { conversationId = {range = cIdRange, int = cId}, detailTypeSet = detailTypeSet }
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

local function parseUpdateSourceRegistrationRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	return { converstationId = {range = cIdRange, int = cId}, topicPath = topicPath }
end

local function parseContent( range )
	local encodingRange = range:range( 0, 1 )
	local lengthRange, remaining, length = varint( range:range( 1 ) )
	local bytesRange = remaining
	return {
		encoding = { range = encodingRange, int = encodingRange:int() },
		length = { range = lengthRange, int = length },
		bytes = { range = bytesRange }
	}
end

local function parseUpdate( range )
	local updateTypeRange = range:range( 0, 1 )
	local updateType = updateTypeRange:int()
	if updateType == 0x00 then
		local actionRange = range:range( 1, 1 )
		local content = parseContent( range:range( 2 ) )
		return {
			updateType = { range = updateTypeRange, int = updateType },
			updateAction = { range = actionRange, int = actionRange:int() },
			content = content
		}
	else
		return {
			updateType = { range = updateTypeRange, int = updateType }
		}
	end
end

local function parseUpdateSourceUpdateRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	local update = parseUpdate( topicPath.remaining )
	return { converstationId = {range = cIdRange, int = cId}, topicPath = topicPath, update = update }
end

local function parseNonExclusiveUpdateRequest( range )
	local topicPath = lengthPrefixedString( range )
	local update = parseUpdate( topicPath.remaining )
	return { topicPath = topicPath, update = update }
end

local function parseUpdateSourceStateRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local oldStateByteRange = remaining:range( 0, 1 )
	local newStateByteRange = remaining:range( 1, 1 )
	return {
		converstationId = {range = cIdRange, int = cId},
		oldUpdateSourceState = { range = oldStateByteRange, int = oldStateByteRange:int() },
		newUpdateSourceState = { range = newStateByteRange, int = newStateByteRange:int() }
	}
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

local function parseUpdateSourceRegistrationResponse( range )
	local stateByteRange = range:range( 0, 1 )
	return { range = stateByteRange, int = stateByteRange:int() }
end

-- Parse the message as a service request or response
local function parseAsV4ServiceMessage( range )
	if range ~= nil and range:len() >= 2 then
		-- Parse service header
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
			-- Store the request so the response time can be caluclated
			local session = tcpConnections[tcpStream]
			local isClient = session.client:matches( f_src_host(), f_src_port() )
			if isClient then
				-- Request is from the client so the client created the conversation Id
				serviceMessageTable:addRequest( tcpStream, session.client, conversation, f_time_epoch() )
			else
				-- Request is from the server so the server created the conversation Id
				serviceMessageTable:addRequest( tcpStream, session.server, conversation, f_time_epoch() )
			end

			-- Parse the request for service specific information
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
			elseif service == v5.SERVICE_UPDATE_SOURCE_REGISTRATION then
				local info = parseUpdateSourceRegistrationRequest( serviceBodyRange )
				result.updateSourceInfo = info
			elseif service == v5.SERVICE_UPDATE_SOURCE_UPDATE then
				local info = parseUpdateSourceUpdateRequest( serviceBodyRange )
				result.updateInfo = info
			elseif service == v5.SERVICE_UPDATE_SOURCE_STATE then
				local info = parseUpdateSourceStateRequest( serviceBodyRange )
				result.oldUpdateSourceState = info.oldUpdateSourceState
				result.newUpdateSourceState = info.newUpdateSourceState
			elseif service == v5.SERVICE_UPDATE_TOPIC then
				local info = parseNonExclusiveUpdateRequest( serviceBodyRange );
				result.updateInfo = info
			elseif service == v5.SERVICE_SESSION_LISTENER_REGISTRATION then
				local info = parseSessionDetailsListenerRegistrationRequest( serviceBodyRange );
				result.sessionListenerRegInfo = info
			end

		elseif  mode == v5.MODE_RESPONSE then

			-- Parse the response for service specific information
			if service == v5.SERVICE_UPDATE_SOURCE_REGISTRATION then
				local info = parseUpdateSourceRegistrationResponse( serviceBodyRange )
				result.newUpdateSourceState = info
			end

			-- Calculate the response time
			local reqTime
			local session = tcpConnections[tcpStream]
			local isClient = session.client:matches( f_src_host(), f_src_port() )
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

-- Package footer
master.parseService = {
	parseAsV4ServiceMessage = parseAsV4ServiceMessage
}
diffusion = master
return master.parseService
