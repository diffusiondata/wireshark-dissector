
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parseCommon ~= nil then
	return master.parseCommon
end

-- Decode the varint used by command serialiser
-- Takes a range containing the varint
-- Returns: a range containing the varint, a range excluding the varint, the
-- numeric value of the varint
local function varint( range )
	local sum = 0
	local idx = 0
	local shift = 0

	if range:len() == 1 then
		local r = range:range( 0, 1 )
		return r, range:range( 0, 0 ), r:uint()
	end

	while shift < 32 do
		local byte = range:range( idx, 1 ):uint()
		sum = bit32.bor( sum, bit32.lshift( bit32.band( byte, 0x7F ), shift ) )

		idx = idx + 1
		if bit32.band( byte, 0x80 ) == 0 then
			break
		end

		shift = shift + 7;
	end

	if idx == range:len() then
		return range:range( 0, idx ), range:range( 0, 0 ), sum
	else
		return range:range( 0, idx ), range:range( idx ), sum
	end
end

-- Decode the varint used by command serialiser
-- Takes a range containing the varint
-- Returns: a range containing the varint, a range excluding the varint, the UInt64 value of the varint
local function varint64( range )
	if range:len() == 1 then
		local r = range:range( 0, 1 )
		return r, range:range( 0, 0 ), UInt64.new( r:uint(), 0 )
	end

	local idx = 0
	local shift = 0

	local sum = UInt64.new( 0, 0 )
	while shift < 64 do
		local byte = range:range( idx, 1 ):uint()
		sum = sum:bor( UInt64.new( bit32.band( byte, 0x7F ), 0 ):lshift( shift ) )

		idx = idx + 1
		if bit32.band( byte, 0x80 ) == 0 then
			break
		end

		shift = shift + 7;
	end

	return range:range( 0, idx ), range:range( idx ), sum
end

local function lengthPrefixedString( range )
	if range ~= nil then
		local lengthRange, rRange, length = varint( range )
		local fullLength = lengthRange:len() + length

		if length == 0 then
			return { range = range:range( 0, 0 ), fullRange = lengthRange, string = "", remaining = rRange }
		end

		local stringRange = rRange:range( 0, length )
		if rRange:len() > length then
			local remainingRange = rRange:range( length )
			return { range = stringRange, remaining = remainingRange, fullRange = range( 0, fullLength ), string = stringRange:string() }
		else
			return { range = stringRange, fullRange = range( 0, fullLength ), string = stringRange:string() }
		end
	end
end

local clientTypesByChar = {
	["J"] = "Java Client",
	["N"] = "HTTP .Net Client",
	["WN"] = "WebSocket .Net Client",
	["F"] = "Flash Bridge Client",
	["S"] = "Silverlight Bridge Client",
	["B"] = "HTTP Browser Client",
	["WJ"] = "WebSocket Java Client",
	["WB"] = "WebSocket Browser Client",
	["I"] = "Introspector Client",
	["WI"] = "WebSocket Introspector Client",
	["W"] = "HTTP Windows Phone Client",
	["F"] = "Flash Client",
	["CA"] = "Flash Comet (HTTPC) Client",
	["FA"] = "HTTP Flash Client",
	["SA"] = "HTTP Silverlight Client",
	["BS"] = "IFrame Streaming Client"
}

local function lookupClientTypeByChar( clientType )
	local type = clientTypesByChar[clientType]
	if type == nil then
		return "Unknown client type"
	else
		return type
	end
end

-- Parse a session ID that uses fixed length encoding
local function parseSessionId( tvb )
	local serverIdentity = tvb( 0, 8 ):uint64()
	local clientIdentity = tvb( 8, 8 ):uint64()
	return {
		serverIdentity = serverIdentity,
		clientIdentity = clientIdentity,
		range = tvb( 0, 16 ),
		clientId = string.format(
			"%s-%s",
			string.upper( serverIdentity:tohex() ),
			string.upper( clientIdentity:tohex() )
		)
	}
end

-- Parse a session ID that uses variable length encoding
-- Currently parses the correct length but not value
local function parseVarSessionId( tvb )
	local serverIdentityRange, remaining, serverIdentity = varint64( tvb )
	local clientIdentityRange, remaining, clientIdentity = varint64( remaining )

	return {
		serverIdentity = serverIdentity,
		clientIdentity = clientIdentity,
		range = tvb( 0, serverIdentityRange:len() + clientIdentityRange:len() ),
		clientId = string.format(
			"%s-%s",
			string.upper( serverIdentity:tohex() ),
			string.upper( clientIdentity:tohex() )
		)
	}, remaining
end

local function parseOptional( tvb, task )
	local optionRange = tvb:range( 0, 1 )
	local option = optionRange:int()
	if option == 0x00 then
		return {
			remaining = tvb:range( 1 )
		}
	else
		return task( tvb:range( 1 ) )
	end
end

-- Package footer
master.parseCommon = {
	varint = varint,
	lengthPrefixedString = lengthPrefixedString,
	lookupClientTypeByChar = lookupClientTypeByChar,
	parseSessionId = parseSessionId,
	parseVarSessionId = parseVarSessionId,
	parseOptional = parseOptional
}
diffusion = master
return master.parseCommon
