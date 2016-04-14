
-- Display package
-- This package adds information to the dissection tree that is displayed in Wireshark. 

-- Package header
local master = diffusion or {}
if master.display ~= nil then
	return master.display
end
local dptProto = diffusion.proto.dptProto
local lookupServiceName = diffusion.displayService.lookupServiceName
local lookupModeName = diffusion.displayService.lookupModeName
local lookupStatusName = diffusion.displayService.lookupStatusName
local hasSelector = diffusion.displayService.hasSelector

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

-- Add the description of the packet to the displayed columns
local function addDescription( pinfo, messageType, headerInfo, serviceInformation, descriptions )
	-- Add the description from the service information
	if serviceInformation ~= nil then
		-- Lookup service and mode name
		local serviceId = serviceInformation.id.int
		local mode = serviceInformation.mode.int
		local serviceString = lookupServiceName( serviceId )
		local modeString = lookupModeName( mode )

		-- Lookup service status
		if serviceInformation.status ~= nil then
			local status = serviceInformation.status.range:int()
			local statusString = lookupStatusName( status )
			modeString = string.format( "%s %s", modeString, statusString)
		end

		if hasSelector( serviceId ) then
			-- Handle services that benefit from a selector in the description
			if serviceInformation.selector ~= nil then
				pinfo.cols.info = string.format( "Service: %s %s '%s'", serviceString, modeString, serviceInformation.selector.string )
				descriptions:addDescription( string.format( "Service: %s %s '%s'", serviceString, modeString, serviceInformation.selector.string ) )
			else
				pinfo.cols.info = string.format( "Service: %s %s", serviceString, modeString )
				descriptions:addDescription( string.format( "Service: %s %s", serviceString, modeString ) )
			end
		else
			pinfo.cols.info = string.format( "Service: %s %s", serviceString, modeString )
			descriptions:addDescription( string.format( "Service: %s %s", serviceString, modeString ) )
		end
		return
	end

	-- Add the description from the message type
	pinfo.cols.info = messageType:getDescription()
	descriptions:addDescription( messageType:getDescription() )
end

local function summariseDescriptions( descriptions )
	if descriptions.count == 1 then
		return descriptions[0]
	end

	local desc = string.format( "%d messages", descriptions.count )
	for i = 0, descriptions.count - 1 do
		desc = desc .. " [" .. descriptions[i] .. "]"
		if i < descriptions.count - 1 then
			desc = desc .. ","
		end
	end
	return desc
end

-- Package footer
master.display = {
	addHeaderInformation = addHeaderInformation,
	addBody = addBody,
	addDescription = addDescription,
	summariseDescriptions = summariseDescriptions
}
diffusion = master
return master.display
