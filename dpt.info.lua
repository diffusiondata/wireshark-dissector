
-- Info package
-- This package provides information tables that are built up and maintained over the course of the dissection.

-- Package header
local master = diffusion or {}
if master.info ~= nil then
	return master.info
end


-- -----------------------------------
-- The Alias Table

local AliasTable = {}

function AliasTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end

function AliasTable:setAlias( tcpStream, alias, topicName )
	-- Get the table for the tcpStream, or create a new one
	local conversation = self[tcpStream] or {}
	conversation[alias] = topicName
	self[tcpStream] = conversation
end

function AliasTable:getAlias( tcpStream, alias )
	local conversation = self[tcpStream]
	if conversation == nil then
		return nil
	end
	return conversation[alias]
end

local aliasTable = AliasTable:new()

-- ------------------------------------
-- The EndpointTable Table
local EndpointTable = {}
function EndpointTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end
function EndpointTable:add( host, port, server )
	local machine = self[host] or {}
	machine[port] = server
	self[host] = machine
end
function EndpointTable:get( host, port )
	return self[host][port]
end

local clientTable = EndpointTable:new()
local serverTable = EndpointTable:new()

-- -----------------------------------
-- Create and register a listener for TCP connections

local tcpConnections = {}
function tcpConnections:len()
	local result = 0
	local i,v
	for i,v in pairs( self ) do result = result +1 end
	return result
end


-- -----------------------------------
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


-- -----------------------------------
-- The Topic Info Table

local TopicInfoTable = {}

function TopicInfoTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end

function TopicInfoTable:setInfo( tcpStream, id, topicPath, topicDetails )
	-- Get the table for the tcpStream, or create a new one
	local stream = self[tcpStream] or {}
	local info = stream[id] or {}
	info.topicPath = topicPath
	info.topicDetails = topicDetails
	stream[id] = info
	self[tcpStream] = stream
end

function TopicInfoTable:getTopicPath( tcpStream, id )
	if self[tcpStream] == nil then
		return nil
	end
	if self[tcpStream][id] == nil then
		return nil
	end
	return self[tcpStream][id].topicPath
end

function TopicInfoTable:getTopicDetails( tcpStream, id )
	if self[tcpStream] == nil then
		return nil
	end
	if self[tcpStream][id] == nil then
		return nil
	end
	return self[tcpStream][id].topicDetails
end

local topicInfoTable = TopicInfoTable:new()

-- Package footer
master.info = {
	aliasTable = aliasTable,
	tcpConnections = tcpConnections,
	topicInfoTable = topicInfoTable,
	clientTable = clientTable,
	serverTable = serverTable,
	serviceMessageTable = serviceMessageTable
}
diffusion = master
return master.info
