
-- Display package
-- This package adds information to the dissection tree that is displayed in Wireshark. 

-- Package header
local master = diffusion or {}
if master.display ~= nil then
	return master.display
end
local dptProto = diffusion.proto.dptProto
local serviceIdentity = diffusion.v5.serviceIdentity
local modeValues = diffusion.v5.modeValues
local statusResponseBytes = diffusion.proto.statusResponseBytes

local v5 = diffusion.v5

-- Attach the connection request information to the dissection tree
local function addConnectionRequest( tree , fullRange, pinfo, request )
	pinfo.cols.info = string.format( "Connection request" )
	local messageTree = tree:add( dptProto, fullRange )
	messageTree:add( dptProto.fields.connectionMagicNumber, request.magicNumberRange )
	messageTree:add( dptProto.fields.connectionProtoNumber, request.protoVerRange )
	messageTree:add( dptProto.fields.connectionType, request.connectionTypeRange )
	messageTree:add( dptProto.fields.capabilities, request.capabilitiesRange )
	if request.creds ~= nil then
		messageTree:add( dptProto.fields.loginCreds, request.creds.range, request.creds.string )
	end
	if request.topicsetRange ~= nil then
		messageTree:add( dptProto.fields.loginTopics, request.topicsetRange )
	end
end

-- Attach the connection response information to the dissection tree
local function addConnectionResponse( tree , fullRange, pinfo, response )
	pinfo.cols.info = string.format( "Connection response" )
	local messageTree = tree:add( dptProto, fullRange )
	messageTree:add( dptProto.fields.connectionMagicNumber, response.magicNumberRange )
	messageTree:add( dptProto.fields.connectionProtoNumber, response.protoVerRange )
	messageTree:add( dptProto.fields.connectionResponse, response.connectionResponseRange )
	messageTree:add( dptProto.fields.messageLengthSize, response.messageLengthSizeRange )
	messageTree:add( dptProto.fields.clientID, response.clientIDRange )
end

-- Attach the handshake information to the dissection tree
local function addConnectionHandshake( tree , fullRange, pinfo, handshake )
	if handshake.request then
		addConnectionRequest( tree, fullRange, pinfo, handshake )
	else
		addConnectionResponse( tree, fullRange, pinfo, handshake )
	end
end

local function addClientConnectionInformation( tree, tvb, client, srcHost, srcPort )
	if client ~= nil then
		local rootNode = tree:add( dptProto.fields.connection )
		rootNode:add( dptProto.fields.clientID, tvb(0,0), client.clientId ):set_generated()
		rootNode:add( dptProto.fields.connectionProtoNumber , tvb(0,0), client.protoVersion ):set_generated()
		rootNode:add( dptProto.fields.connectionType, tvb(0,0), client.connectionType ):set_generated()
		rootNode:add( dptProto.fields.capabilities, tvb(0,0), client.capabilities ):set_generated()
		if client:matches( srcHost, srcPort ) then
			rootNode:add( dptProto.fields.direction, tvb(0,0), "Client to Server" ):set_generated()
		else
			rootNode:add( dptProto.fields.direction, tvb(0,0), "Server to Client" ):set_generated()
		end
	else
		tree:add( dptProto.fields.connection, tvb(0,0), "Connection unknown, partial capture" )
	end
end

-- Add topic and alias information to dissection tree
local function addTopicHeaderInformation( treeNode, info )
	if info.alias.range ~= nil then
		treeNode:add( dptProto.fields.alias, info.alias.range, info.alias.string )
	end
	if info.topic.resolved then
		local node = treeNode:add( dptProto.fields.topic, info.topic.range, info.topic.string )
		node:append_text(" (resolved from alias)")
		node:set_generated()
	else
		treeNode:add( dptProto.fields.topic, info.topic.range, info.topic.string )
	end
end

-- Add information from the header parsing
local function addHeaderInformation( headerNode, info )
	if info ~= nil then
		if info.topic ~= nill then
			addTopicHeaderInformation( headerNode, info.topic ) 
		end
		if info.fixedHeaders ~= nil then
			headerNode:add( dptProto.fields.fixedHeaders, info.fixedHeaders.range, info.fixedHeaders.string )
		end
		if info.userHeaders ~= nil then
			headerNode:add( dptProto.fields.userHeaders, info.userHeaders.range, info.userHeaders.string )
		end
		if info.parameters ~= nil then
			headerNode:add( dptProto.fields.parameters, info.parameters.range, info.parameters.string )
		end
		if info.command ~= nil then
			headerNode:add( dptProto.fields.command, info.command.range, info.command.string )
		end
		if info.commandTopicType ~= nil then
			headerNode:add( dptProto.fields.commandTopicType, info.commandTopicType.range, info.commandTopicType.string )
		end
		if info.commandCategory ~= nil then
			headerNode:add( dptProto.fields.commandTopicCategory, info.commandCategory.range, info.commandCategory.string )
		end
		if info.notificationType ~= nil then
			headerNode:add( dptProto.fields.notificationType, info.notificationType.range, info.notificationType.string )
		end
		if info.timestamp ~= nil then
			headerNode:add( dptProto.fields.timestamp, info.timestamp.range, info.timestamp.string )
		end
		if info.queueSize ~= nil then
			headerNode:add( dptProto.fields.queueSize, info.queueSize.range, info.queueSize.string )
		end
		if info.ackId ~= nil then
			headerNode:add( dptProto.fields.ackId, info.ackId.range, info.ackId.string )
		end
	end
end

local function addBody( parentTreeNode, records )
	if records.range == nil then
		-- If the body is not parsed (eg. unsupported encoding) then do not try to add anything to the body
		return
	end
	local bodyNode = parentTreeNode:add( dptProto.fields.content, records.range, string.format( "%d bytes", records.range:len() ) )
	if records.num == 1 then
		bodyNode:append_text( ", 1 record" )
	else
		bodyNode:append_text( string.format( ", %d records", records.num ) )
	end
	if records ~= nil then
		for i, record in ipairs(records) do
			local recordNode = bodyNode:add( dptProto.fields.record, record.range, record.string )
			recordNode:set_text( string.format( "Record %d: %s", i, record.string ) )

			if record.fields ~= nil then
				if record.fields.num == 1 then
					recordNode:set_text( string.format( "Record %d: %d bytes, 1 field", i, record.range:len() ) )
				else
					recordNode:set_text( string.format( "Record %d: %d bytes, %d fields", i, record.range:len(), record.fields.num ) )
				end
				for j, field in ipairs(record.fields) do
					local fieldNode = recordNode:add( dptProto.fields.field, field.range, field.string )
					fieldNode:set_text( string.format( "Field %d: %s [%d bytes]", j, field.string, field.range:len() ) )
				end
			end
		end
	end
end

local function addTopicDetails( parentNode, details )
	parentNode:add( dptProto.fields.topicType, details.type.range, details.type.type )
end

local function addServiceInformation( parentTreeNode, service )
	if service ~= nil and service.range ~= nil then
		local serviceNodeDesc = string.format( "%d bytes", service.range:len() )
		-- Create service node
		local serviceNode = parentTreeNode:add( dptProto.fields.service, service.range, serviceNodeDesc )
		serviceNode:add( dptProto.fields.serviceIdentity, service.id.range, service.id.int )
		serviceNode:add( dptProto.fields.serviceMode, service.mode.range, service.mode.int )
		serviceNode:add( dptProto.fields.conversation, service.conversation.range, service.conversation.int )

		if service.selector ~= nil then
			serviceNode:add( dptProto.fields.selector, service.selector.range, service.selector.string )
		end
		if service.status ~= nil then
			serviceNode:add( dptProto.fields.status, service.status.range )
		end
		if service.topicName ~= nil then
			serviceNode:add( dptProto.fields.topicName, service.topicName.fullRange, service.topicName.string )
		end
		if service.topicInfo ~= nil then
			local topicInfoNodeDesc = string.format( "%d bytes", service.topicInfo.range:len() )
			local topicInfoNode = serviceNode:add( dptProto.fields.topicInfo, service.topicInfo.range, topicInfoNodeDesc )
			topicInfoNode:add( dptProto.fields.topicId, service.topicInfo.id.range, service.topicInfo.id.int )
			topicInfoNode:add( dptProto.fields.topicPath, service.topicInfo.path.range, service.topicInfo.path.string )
			addTopicDetails( topicInfoNode, service.topicInfo.details )
		end
		if service.topicUnsubscriptionInfo ~= nil then
			serviceNode:add( dptProto.fields.topicName, service.topicUnsubscriptionInfo.topic.range, service.topicUnsubscriptionInfo.topic.name )
			serviceNode:add( dptProto.fields.topicUnSubReason, service.topicUnsubscriptionInfo.reason.range, service.topicUnsubscriptionInfo.reason.reason )
		end
	end
end

local function addDescription( pinfo, messageType, headerInfo, serviceInformation )
	if serviceInformation ~= nil then
		local serviceId = serviceInformation.id.int
		local mode = serviceInformation.mode.int
		local serviceString = serviceIdentity[serviceId]
		local modeString = modeValues[mode]
		if serviceString == nil then
			serviceString = string.format( "Unknown service (%d)", serviceId )
		end
		if serviceString == nil then
			modeString = string.format( "Unknown mode (%d)", mode )
		end
		if serviceInformation.status ~= nil then
			local status = serviceInformation.status.range:int()
			local statusString = statusResponseBytes[status]
			if statusString == nil then
				statusString = string.format( "Unknown status (%d)", status )
			end
			modeString = string.format( "%s %s", modeString, statusString)
		end
		if serviceId == v5.SERVICE_FETCH or
			serviceId == v5.SERVICE_SUBSCRIBE or
			serviceId == v5.SERVICE_UNSUBSCRIBE then
			if serviceInformation.selector ~= nil then
				pinfo.cols.info = string.format( "Service: %s %s '%s'", serviceString, modeString, serviceInformation.selector.string )
			else
				pinfo.cols.info = string.format( "Service: %s %s ", serviceString, modeString )
			end
		else
			pinfo.cols.info = string.format( "Service: %s %s ", serviceString, modeString )
		end
		return
	end
	pinfo.cols.info = messageType:getDescription()
end

-- Package footer
master.display = {
	addConnectionHandshake = addConnectionHandshake,
	addClientConnectionInformation = addClientConnectionInformation,
	addHeaderInformation = addHeaderInformation,
	addBody = addBody,
	addServiceInformation = addServiceInformation,
	addDescription = addDescription
}
diffusion = master
return master.display
