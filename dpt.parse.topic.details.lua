
-- Parse package
-- This package provides parsing support for the topic details

-- Package header
local master = diffusion or {}
if master.parseService ~= nil then
	return master.parseTopicDetails
end

local function parseAttributes( range )
	--TODO: Attribute parsing
end

local function parseSchema( range )
	--TODO: Schema parsing
end

local function parseTopicDetails( detailsRange )
	local any = detailsRange:range( 0, 1 )
	if any:int() == 0 then
		return { range = any, type = { type = 0, range = any } }
	else
		local type = detailsRange:range( 1, 1 )
		local typeRange = detailsRange:range( 0, 2 )
		if detailsRange:range( 2, 1 ):int() == 0 then
			-- Basic
			return { range = detailsRange:range( 0, 3 ), type = { type = type:int(), range = typeRange } }
		else
			-- Schema+
			local schema = parseSchema( detailsRange:range( 3 ) )
			return { range = typeRange, type = { type = type:int(), range = typeRange } }
		end
	end
end

-- Package footer
master.parseTopicDetails = {
	parse = parseTopicDetails
}
diffusion = master
return master.parseTopicDetails
