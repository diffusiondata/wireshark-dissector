
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

-- -----------------------------------
-- Create and register a listener for TCP connections

local tcpConnections = {}
function tcpConnections:len()
	local result = 0
	local i,v
	for i,v in pairs( self ) do result = result +1 end
	return result
end


-- Package footer
master.info = {
	aliasTable = aliasTable,
	tcpConnections = tcpConnections
}
diffusion = master
return master.info
