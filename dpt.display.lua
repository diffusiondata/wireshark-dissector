
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

		-- Add command header
		serviceNode:add( dptProto.fields.serviceIdentity, service.id.range, service.id.int )
		serviceNode:add( dptProto.fields.serviceMode, service.mode.range, service.mode.int )
		serviceNode:add( dptProto.fields.conversation, service.conversation.range, service.conversation.int )

		-- Add service specific information
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
		if service.controlRegInfo ~= nil then
			serviceNode:add( dptProto.fields.regServiceId, service.controlRegInfo.serviceId.range, service.controlRegInfo.serviceId.int )
			serviceNode:add( dptProto.fields.controlGroup, service.controlRegInfo.controlGroup.fullRange, service.controlRegInfo.controlGroup.string )
		end
		if service.handlerName ~= nil then
			serviceNode:add( dptProto.fields.handlerName, service.handlerName.fullRange, service.handlerName.string )
		end
		if service.handlerTopicPath ~= nil then
			serviceNode:add( dptProto.fields.handlerTopicPath, service.handlerTopicPath.fullRange, service.handlerTopicPath.string )
		end
		if service.updateSourceInfo ~= nil then
			serviceNode:add( dptProto.fields.updateSourceTopicPath, service.updateSourceInfo.topicPath.fullRange, service.updateSourceInfo.topicPath.string )
		end
		if service.updateInfo ~= nil then
			serviceNode:add( dptProto.fields.topicName, service.updateInfo.topicPath.fullRange, service.updateInfo.topicPath.string )
			local update = service.updateInfo.update;
			serviceNode:add( dptProto.fields.updateType, update.updateType.range, update.updateType.int )
			if update.updateAction ~= nil then
				serviceNode:add( dptProto.fields.updateAction, update.updateAction.range, update.updateAction.int )
				serviceNode:add( dptProto.fields.encodingHdr, update.content.encoding.range, update.content.encoding.int )
				serviceNode:add( dptProto.fields.contentLength, update.content.length.range, update.content.length.int )
				serviceNode:add( dptProto.fields.content, update.content.bytes.range )
			end
		end
		if service.newUpdateSourceState ~= nil then
			serviceNode:add( dptProto.fields.newUpdateSourceState, service.newUpdateSourceState.range, service.newUpdateSourceState.int )
		end
		if service.oldUpdateSourceState ~= nil then
			serviceNode:add( dptProto.fields.oldUpdateSourceState, service.oldUpdateSourceState.range, service.oldUpdateSourceState.int )
		end

		-- Add generated information
		if service.responseTime ~= nil then
			local node = serviceNode:add( dptProto.fields.responseTime, service.responseTime )
			node:set_generated()
		end
	end
end

-- Add the description of the packet to the displayed columns
local function addDescription( pinfo, messageType, headerInfo, serviceInformation )
	-- Add the description from the service information
	if serviceInformation ~= nil then
		-- Lookup service and mode name
		local serviceId = serviceInformation.id.int
		local mode = serviceInformation.mode.int
		local serviceString = serviceIdentity[serviceId]
		local modeString = modeValues[mode]

		-- Handle unknown values
		if serviceString == nil then
			serviceString = string.format( "Unknown service (%d)", serviceId )
		end
		if modeString == nil then
			modeString = string.format( "Unknown mode (%d)", mode )
		end

		-- Lookup service status
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
			-- Handle services that benefit from a selector in the description
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

	-- Add the description from the message type
	pinfo.cols.info = messageType:getDescription()
end

-- Package footer
master.display = {
	addHeaderInformation = addHeaderInformation,
	addBody = addBody,
	addServiceInformation = addServiceInformation,
	addDescription = addDescription
}
diffusion = master
return master.display
