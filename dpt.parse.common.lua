
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
-- TODO: Unit test
local function varint( range )
	local sum = 0
	local idx = 0
	local shift = 0

	if range:len() == 1 then
		local r = range:range( 0, 1 )
		return r, range:range( 0, 0 ), r:uint()
	end

	while idx + 1 < range:len() do
		local byte = range:range( idx, 1 ):uint()
		if byte >= 128 then
			sum = sum + ( shift + byte - 128 )
			idx = idx + 1
			shift = shift + ( 2 ^ idx * 8 )
		else
			sum = sum + ( shift + byte )
			idx = idx + 1
			break
		end
	end
	return range:range( 0, idx ), range:range( idx ), sum
end

local function varint64( range )
	local idx = 0

	if range:len() == 1 then
		local r = range:range( 0, 1 )
		return r, range:range( 0, 0 ), r:uint()
	end

	while idx + 1 < range:len() do
		local byte = range:range( idx, 1 ):uint()
		if byte >= 128 then
			idx = idx + 1
		else
			idx = idx + 1
			break
		end
	end

	-- Get low 32
	local lo = 0
	-- TODO

	-- Get hi 32
	local hi = 0
	-- TODO

	return range:range( 0, idx ), range:range( idx ), UInt64.new( lo, hi )
end

local function lengthPrefixedString( range )
	if range ~= nil then
		local lengthRange, rRange, length = varint( range )
		local fullLength = lengthRange:len() + length

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

-- Package footer
master.parseCommon = {
	varint = varint,
	lengthPrefixedString = lengthPrefixedString,
	lookupClientTypeByChar = lookupClientTypeByChar,
	parseSessionId = parseSessionId,
	parseVarSessionId = parseVarSessionId
}
diffusion = master
return master.parseCommon
