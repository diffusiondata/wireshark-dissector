
-- Messages package
-- This package describes and parses different message types sent by Diffusion.

-- Package header
local master = diffusion or {}
if master.messages ~= nil then
	return master.messages
end

local RD, FD = diffusion.utilities.RD, diffusion.utilities.FD

local parseTopicHeader = diffusion.parse.parseTopicHeader
local parseRecordFields = diffusion.parse.parseRecordFields
local parseField = diffusion.parse.parseField
local parseAckId = diffusion.parse.parseAckId


-- -----------------------------------
-- A 'class' to process message types

local MessageType = {}

function MessageType:new( id, name, fixedHeaderCount)
	local result = { id = id, name = name, fixedHeaderCount = fixedHeaderCount }
	setmetatable( result, self )
	self.__index = self
	return result
end

-- Iterate across an array of MessageType object, and produce a table of the same indexed by the ID
function MessageType.index( typeArray )
	local result = {}
	for i, type in ipairs(typeArray) do
		result[type.id] = type
	end
	return result
end

-- Populate the headers tree with separate fixed headers and user headers
function MessageType:markupHeaders( headerRange )
	-- Find the RD marking the fixed|user boundary
	local headerBreak = headerRange:bytes():indexn( FD, self.fixedHeaderCount -1 )
	if headerBreak == -1 then
		-- no user headers, only fixed headers
		return { fixedHeaders = { range = headerRange, string = headerRange:string():escapeDiff() } }
	else
		-- fixed headers and user headers
		local fixedHeaderRange = headerRange:range( 0, headerBreak )
		local userHeaderRange = headerRange:range( headerBreak +1 )
		return { fixedHeaders = { range = fixedHeaderRange, string = fixedHeaderRange:string():escapeDiff() },
			userHeaders = { range = userHeaderRange, string = userHeaderRange:string():escapeDiff() } }
	end
end

function MessageType:markupBody( messageDetails, bodyRange )
	-- the payload, everything after the headers

	if messageDetails.msgEncoding == 0 then
		local rangeBase = 0
		local bodyString = bodyRange:string()
		local records = bodyString:split( string.char( RD ) )
		local recs = { num = #records, range = bodyRange }

		-- Break open into records & then fields
		for i, record in ipairs(records) do

			local recordRange = bodyRange:range( rangeBase, #record )
			local fields = parseRecordFields( recordRange )
			recs[i] = { range = recordRange, string = record:toRecordString(), fields = fields }

			rangeBase = rangeBase + #record + 1 -- +1 for the delimiter
		end
		return recs
	else
		return {}
	end
end

function MessageType:getDescription()
	return self.name
end

-- Functionality specific to Topic Loads

local topicLoadType = MessageType:new( 0x14, "Topic Load", 1 )

function topicLoadType:markupHeaders( headerRange )
	-- Parse topic
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	if alias ~= nil then
		self.loadDescription = string.format( "aliasing %s => topic '%s'", alias, topic )
	else
		self.loadDescription = topic
	end

	local userHeaderObject
	if headerRange ~= nil then
		userHeaderObject = { range = headerRange, string = headerRange:string():escapeDiff() }
	end

	return { topic = info, userHeader = userHeaderObject }
end

function topicLoadType:getDescription()
	return string.format( "%s, %s", self.name, self.loadDescription ) 
end

-- Functionality specific to Delta Messages

local deltaType = MessageType:new( 0x15, "Delta", 1 )

function deltaType:markupHeaders( headerRange )
	-- Parse topic
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	if topic ~= nil then
		self.topicDescription = string.format( "Topic: '%s'", topic )
	else
		self.topicDescription = string.format( "Unknown alias: '%s'", alias )
	end

	local userHeaderObject
	if headerRange ~= nil then
		userHeaderObject = { range = headerRange, string = headerRange:string():escapeDiff() }
		return { topic = info, userHeaders = userHeaderObject }
	end

	return { topic = info, userHeaders = userHeaderObject }
end

function deltaType:getDescription()
	return string.format( "%s, %s", self.name, self.topicDescription ) 
end

-- Functionality specific to Subscriptions - the info column, mostly

local subscribeType = MessageType:new( 0x16, "Subscribe", 1 )

function subscribeType:markupHeaders( headerRange )
	-- A single header, with a topic-selector
	self.subscriptionDescription = string.format( "Subscribe to '%s'", headerRange:string() )
	return { fixedHeaders = { range = headerRange, string = headerRange:string() } }
end

function subscribeType:getDescription()
	return self.subscriptionDescription 
end

-- Functionality specific to Command Messages
local commandMessageType = MessageType:new( 0x24, "Command Message", 2 )

function commandMessageType:markupHeaders( headerRange )
	-- Parse topic
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	local commandEndIndex = headerRange:bytes():index( FD )
	local commandRange
	local commandObject
	local parametersObject
	if commandEndIndex > -1 then
		commandRange = headerRange:range( 0, commandEndIndex )
		commandObject = { range = commandRange, string = commandRange:string() }

		--Parse parameters
		local parametersRange = headerRange:range( commandEndIndex + 1 )
		parametersObject = { range = parametersRange, string = parametersRange:string():escapeDiff() }
	else
		commandRange = headerRange:range( 0 )
		commandObject = { range = commandRange, string = commandRange:string() }
	end
	if topic ~= nil then
		self.commandDescription = string.format ( "Command Message Topic: '%s', Command: '%s'", topic, commandRange:string() )
	elseif alias ~= nil then
		self.commandDescription = string.format ( "Command Message Alias: '%s', Command: '%s'", alias, commandRange:string() )
	else
		self.commandDescription = string.format ( "Command Message Topic: Unknown, Command: '%s'", commandRange:string() )
	end

	return { topic = info, command = commandObject, parameters = parametersObject }
end

function commandMessageType:getDescription()
	return self.commandDescription 
end

-- Functionality specific to Command Topic Load
local commandTopicLoadType = MessageType:new( 0x28, "Command Topic Load", 3 )

function commandTopicLoadType:markupHeaders( headerRange )
	-- Parse topic
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	-- Parse command topic category
	local commandTopicCategoryEndIndex = headerRange:bytes():index( FD )
	local commandTopicCategoryRange = headerRange:range( 0, commandTopicCategoryEndIndex )
	local commandTopicCategoryObject = { range = commandTopicCategoryRange, string = commandTopicCategoryRange:string() }

	-- Parse command Topic Type
	headerRange = headerRange:range( commandTopicCategoryEndIndex + 1 )
	local commandTopicTypeEndIndex = headerRange:bytes():index( FD )
	local commandRange, commandTopicTypeObject, parametersObject, commandTopicTypeRange
	if commandTopicTypeEndIndex > -1 then
		commandTopicTypeRange = headerRange:range( 0, commandTopicTypeEndIndex )
		commandTopicTypeObject = { range = commandTopicTypeRange, string = commandTopicTypeRange:string() }

		--Parse parameters
		local parametersRange = headerRange:range( commandTopicTypeEndIndex + 1 )
		parametersObject = { range = parametersRange, string = parametersRange:string():escapeDiff() }
	else
		commandTopicTypeRange = headerRange:range( 0 )
		commandTopicTypeObject = { range = commandTopicTypeRange, string = commandTopicTypeRange:string() }
	end
	if topic ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Load Topic: %s Topic Category: %s", topic, commandTopicCategoryRange:string() )
	elseif alias ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Load Alias: %s Topic Category: %s", alias, commandTopicCategoryRange:string() )
	else
		self.commandTopicLoadDescription = string.format ( "Command Load Topic: Unknown Topic Category: %s", commandTopicCategoryRange:string() )
	end

	return { topic = info, parameters = parametersObject, commandCategory = commandTopicCategoryObject, commandTopicType = commandTopicTypeObject }
end

function commandTopicLoadType:getDescription( messageDetails )
	return self.commandTopicLoadDescription 
end

-- Functionality specific to Command Topic Notification
local commandTopicNotificationType = MessageType:new( 0x29, "Command Topic Notification", 2 )

function commandTopicNotificationType:markupHeaders( headerRange )
	-- Parse topic
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	-- Parse notification type
	local notificationTypeEndIndex = headerRange:bytes():index( FD )
	local notificationTypeRange, notificationTypeObject, parametersObject
	if notificationTypeEndIndex > -1 then
		notificationTypeRange = headerRange:range( 0, notificationTypeEndIndex )
		notificationTypeObject = { range = notificationTypeRange, string = notificationTypeRange:string() }

		--Parse parameters
		local parametersRange = headerRange:range( notificationTypeEndIndex + 1 )
		parametersObject = { range = parametersRange, string = parametersRange:string():escapeDiff() }
	else
		notificationTypeRange = headerRange:range( 0 )
		notificationTypeObject = { range = notificationTypeRange, string = notificationTypeRange:string() }
	end
	if topic ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Notification Topic: %s Notification Type: %s", topic, notificationTypeRange:string() )
	elseif alias ~= nil then
		self.commandTopicLoadDescription = string.format ( "Command Notification Alias: %s Notification Type: %s", alias, notificationTypeRange:string() )
	else
		self.commandTopicLoadDescription = string.format ( "Command Notification Topic: Unknown Notification Type: %s", notificationTypeRange:string() )
	end

	return { topic = info, parameters = parametersObject, notificationType = notificationTypeObject }
end

function commandTopicNotificationType:getDescription()
	return self.commandTopicLoadDescription 
end

local fetchType = MessageType:new( 0x21, "Fetch", 1 )
function fetchType:markupHeaders( headerRange )
	local info
	headerRange, info = parseTopicHeader( headerRange )
	self.fetchDescription = string.format( "Fetch '%s'", info.topic.string )
	return { topic = info }
end
function fetchType:getDescription( )
	return self.fetchDescription
end

local fetchReplyType = MessageType:new( 0x22, "Fetch Reply", 1 )
function fetchReplyType:markupHeaders( headerRange )
	local info
	headerRange, info = parseTopicHeader( headerRange )
	self.fetchDescription = string.format( "Fetch reply '%s'", info.topic.string )
	return { topic = info }
end
function fetchReplyType:getDescription( )
	return self.fetchDescription
end

local pingServer = MessageType:new( 0x18, "Ping Server", 2 )
function pingServer:markupHeaders( headerRange )
	local timestampRange
	timestampRange, headerRange = parseField( headerRange )
	if headerRange ~= nil then
		local messageQueueRange, headerRange = parseField( headerRange )
		return { timestamp = { range = timestampRange, string = timestampRange:string() },
			queueSize = { range = messageQueueRange, string = messageQueueRange:string() } }
	else
		return { timestamp = { range = timestampRange, string = timestampRange:string() } }
	end
end
local pingClient = MessageType:new( 0x19, "Ping Client", 1 )
function pingClient:markupHeaders( headerRange )
	local timestampRange, messageQueueRange
	timestampRange, headerRange = parseField( headerRange )
	return { timestamp = { range = timestampRange, string = timestampRange:string() } }
end

local topicLoadAckType = MessageType:new( 0x1e, "Topic Load - ACK Required", 2)
function topicLoadAckType:markupHeaders( headerRange )
	return topicLoadType.markupHeaders( self, headerRange )
end

local deltaAckType = MessageType:new( 0x1f, "Delta - ACK Required", 2 )
function deltaAckType:markupHeaders( headerRange )
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	if topic ~= nil then
		self.topicDescription = string.format( "Topic: '%s'", topic )
	else
		self.topicDescription = string.format( "Unknown alias: '%s'", alias )
	end

	local ackIdObject
	ackIdObject, headerRange = parseAckId( headerRange )
	self.ackDescription = string.format( "Ack ID %s", ackIdObject.string )

	local userHeaderObject
	if headerRange ~= nil then
		userHeaderObject = { range = headerRange, string = headerRange:string():escapeDiff() }
	end

	return { topic = info, ackId = ackIdObject, userHeader = userHeaderObject }
end
function deltaAckType:getDescription()
	return string.format( "%s, %s, %s", self.name, self.topicDescription, self.ackDescription )
end

local topicLoadAckType = MessageType:new( 0x1e, "Topic Load - ACK Required", 2 )
function topicLoadAckType:markupHeaders( headerRange )
	local info, topic, alias
	headerRange, info = parseTopicHeader( headerRange )
	topic = info.topic.string
	alias = info.alias.string

	if alias ~= nil then
		self.loadDescription = string.format( "aliasing %s => topic '%s'", alias, topic )
	elseif topic == nil then
		self.loadDescription = "Bad topic"
	else
		self.loadDescription = topic
	end

	local ackIdObject
	ackIdObject, headerRange = parseAckId( headerRange )
	self.ackDescription = string.format( "Ack ID %s", ackIdObject.string )

	local userHeaderObject
	if headerRange ~= nil then
		userHeaderObject = { range = headerRange, string = headerRange:string():escapeDiff() }
	end

	return { topic = info, ackId = ackIdObject, userHeader = userHeaderObject }
end
function topicLoadAckType:getDescription()
	return string.format( "%s, %s, %s", self.name, self.loadDescription, self.ackDescription )
end

local ackType = MessageType:new( 0x20, "ACK - acknowledge", 1 )
function ackType:markupHeaders( headerRange )
	local ackIdObject
	ackIdObject, headerRange = parseAckId( headerRange )
	self.ackDescription = string.format( "Ack ID %s", ackIdObject.string )
	return { ackId = ackIdObject }
end
function ackType:getDescription()
	return string.format( "%s, %s", self.name, self.ackDescription )
end

-- The messageType table
local messageTypesByValue = MessageType.index( {
	topicLoadType,
	deltaType,
	subscribeType,
	MessageType:new( 0x17, "Unsubscribe", 1 ),
	pingServer,
	pingClient,
	MessageType:new( 0x1a, "Credentials", 2 ),
	MessageType:new( 0x1b, "Credentials Rejected", 2 ),
	MessageType:new( 0x1c, "Abort Notification", 0 ),
	MessageType:new( 0x1d, "Close Request", 0 ),
	topicLoadAckType,
	deltaAckType,
	ackType,
	fetchType,
	fetchReplyType,
	MessageType:new( 0x23, "Topic Status Notification", 2 ),
	commandMessageType,
	commandTopicLoadType,
	commandTopicNotificationType,
	MessageType:new( 0x30, "Cancel Fragmented Message Set", 1 )
})

local function messageTypeLookup(byte)
	if byte >= 0x40 then
		return messageTypesByValue[byte - 0x40]
	else
		return messageTypesByValue[byte]
	end
end

local function nameByID(byte)
	if byte >= 0x40 then
		return MessageType.nameByID(byte - 0x40) .. " fragmented"
	else
		return messageTypesByValue[byte].name
	end
end


-- Package footer
master.messages = {
	messageTypeLookup = messageTypeLookup,
	nameByID = nameByID
}
diffusion = master
return master.messages
