
-- Main
-- This file is the entry point for the plugin. It loads the other packages and adds listeners to Wireshark and
-- modifies the dissection table

-- This assumes that files are in USER_DIR
-- require looks in wireshark directories.
dofile( USER_DIR.."dpt.utilities.lua" )
dofile( USER_DIR.."dpt.info.lua" )
dofile( USER_DIR.."dpt.v5.lua" )
dofile( USER_DIR.."dpt.parse.lua" )
dofile( USER_DIR.."dpt.messages.lua" )
dofile( USER_DIR.."dpt.proto.lua" )
dofile( USER_DIR.."dpt.display.lua" )
dofile( USER_DIR.."dpt.dissector.lua" )

local u = diffusion.utilities
local i = diffusion.info
local dptProto = diffusion.proto.dptProto
local tcpConnections = diffusion.info.tcpConnections

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

--------------------------------------
-- The Client Table
ClientTable = {}
function ClientTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end
function ClientTable:add( host, port, client )
	local machine = self[host] or {}
	machine[port] = client
	self[host] = machine
end
function ClientTable:get( host, port )
	return self[host][port]
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

--------------------------------------
-- The Server Table
ServerTable = {}
function ServerTable:new()
	local result = {}
	setmetatable( result, self )
	self.__index = self
	return result
end
function ServerTable:add( host, port, server )
	local machine = self[host] or {}
	machine[port] = server
	self[host] = machine
end
function ServerTable:get( host, port )
	return self[host][port]
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local f_frame_number = diffusion.utilities.f_frame_number

local tcpTap = Listener.new( "tcp", "tcp.flags eq 0x12" ) -- listen to SYN,ACK packets (which are sent by the *server*)
function tcpTap.packet( pinfo )
	local streamNumber = f_tcp_stream().value
	local fNumber = f_frame_number().value

	local client = Client:new( u.dstHost(), pinfo.dst_port )
	ClientTable:add( u.dstHost(), pinfo.dst_port, client )
	local server = Server:new( u.srcHost(), pinfo.src_port )
	ServerTable:add( u.dstHost(), pinfo.dst_port, server )

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
