
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

-- Package footer
master.parseCommon = {
	varint = varint,
	lengthPrefixedString = lengthPrefixedString,
	lookupClientTypeByChar = lookupClientTypeByChar
}
diffusion = master
return master.parseCommon
