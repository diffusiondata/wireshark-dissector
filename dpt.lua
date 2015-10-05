
-- Main
-- This file is the entry point for the plugin. It loads the other packages and adds listeners to Wireshark and
-- modifies the dissection table

-- This assumes that files are in USER_DIR
-- require looks in wireshark directories.
dofile( USER_DIR.."dpt.utilities.lua" )
dofile( USER_DIR.."dpt.info.lua" )
dofile( USER_DIR.."dpt.v5.lua" )
dofile( USER_DIR.."dpt.parse.common.lua" )
dofile( USER_DIR.."dpt.parse.service.lua" )
dofile( USER_DIR.."dpt.parse.lua" )
dofile( USER_DIR.."dpt.messages.lua" )
dofile( USER_DIR.."dpt.proto.lua" )
dofile( USER_DIR.."dpt.display.service.lua" )
dofile( USER_DIR.."dpt.display.connection.lua" )
dofile( USER_DIR.."dpt.display.lua" )
dofile( USER_DIR.."dpt.dissector.lua" )

local u = diffusion.utilities
local i = diffusion.info
local dptProto = diffusion.proto.dptProto
local tcpConnections = diffusion.info.tcpConnections
local clientTable = diffusion.info.clientTable
local serverTable = diffusion.info.serverTable

local RD, FD = diffusion.utilities.RD, diffusion.utilities.FD

--------------------------------------
-- Client

Client = {}
function Client:new( host, port )
	local result = { host = host, port = port }
	setmetatable( result, self )
	self.__index = self
	return result
end
function Client:matches( host, port )
	return self.host == host and self.port == port
end
function Client:isClient()
	return true
end

---------------------------------------
-- Server

Server = {}
function Server:new( host, port )
	local result = { host = host, port = port }
	setmetatable( result, self )
	self.__index = self
	return result
end
function Server:matches( host, port )
	return self.host == host and self.port == port
end
function Server:isClient()
	return false
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream

local tcpTap = Listener.new( "tcp", "tcp.flags eq 0x12" ) -- listen to SYN,ACK packets (which are sent by the *server*)

function tcpTap.packet( pinfo )
	local streamNumber = f_tcp_stream()

	local client = Client:new( u.f_dst_host(), pinfo.dst_port )
	clientTable:add( u.f_dst_host(), pinfo.dst_port, client )
	local server = Server:new( u.f_src_host(), pinfo.src_port )
	serverTable:add( u.f_dst_host(), pinfo.dst_port, server )

	tcpConnections[streamNumber] = { 
		client = client,
		server = server
	}

	info( u.dump( tcpConnections ) )
end

function tcpTap.reset()
	info( "resetting tcpConnections" )
end

-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
function ByteArray:indexn(ch, delimiterCount)
	for i = 0, self:len()-1 do
		if self:get_index( i ) == ch then 
			-- Found a match, but is it the right one?
			if delimiterCount == 0 then
				return i
			end
			delimiterCount = delimiterCount -1
		end
	end
	return -1
end

-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
function ByteArray:index(ch)
	for i = 0, self:len()-1 do
		if self:get_index( i ) == ch then return i end
	end
	return -1
end

-- Mark up non-printing delimiters
function string:escapeDiff()
	local result = self:gsub( string.char(RD), "<RD>" )
	return (result:gsub( string.char(FD), "<FD>" ))
end

function string:toRecordString() 
	return string.format( "[%s]", self:gsub( string.char(FD), ", " ) )
end

function string:startsWith( prefix )
	local prefixLength = string.len( prefix )
	local actualPrefix = string.sub( self, 1, prefixLength )
	return actualPrefix == prefix
end

-- Split a string into fields by the given delimited
function string:split(sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

-- Register the dissector
tcp_table = DissectorTable.get( "tcp.port" )
tcp_table:add( 8080, dptProto )
