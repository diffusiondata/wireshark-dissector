
-- Parse package
-- This package provides parsing support for the topic details

-- Package header
local master = diffusion or {}
if master.parseService ~= nil then
	return master.parseTopicDetails
end

local lengthPrefixedString = diffusion.parseCommon.lengthPrefixedString
local varint = diffusion.parseCommon.varint

local function parseTopicProperties( range )
	local numRange, remaining, numberOfProperties = varint( range )
	if numberOfProperties == 0 then
		return {
			number = { range = numRange, number = numberOfProperties }
		}, remaining
	end
	return {
		number = { range = numRange, number = numberOfProperties }
	}, nil
end

local function parseAttributes( type, range )
	local autoSubscribe = range( 0, 1 )
	local tidiesOnUnsubscribe = range( 1, 1 )
	local reference = lengthPrefixedString( range( 2 ) )
	local topicProperties, remainingAfterTopicProperties = parseTopicProperties( reference.remaining )

	if type == diffusion.const.topicTypes.JSON or type == diffusion.const.topicTypes.BINARY then
		return {
			autoSubscribe = autoSubscribe,
			tidiesOnUnsubscribe = tidiesOnUnsubscribe,
			reference = reference,
			topicProperties = topicProperties
		}, remainingAfterTopicProperties
	end
	return {}
end

local function parseSchema( type, range )
	if type == diffusion.const.topicTypes.JSON or type == diffusion.const.topicTypes.BINARY then
		return {}, range
	end
	return nil
end

local function parseTopicDetails( detailsRange )
	local any = detailsRange:range( 0, 1 )
	if any:int() == 0 then
		return { range = any, type = { type = 0, range = any } }
	else
		local type = detailsRange:range( 1, 1 )
		local typeRange = detailsRange:range( 0, 2 )

		local schema, remainingAfterSchema
		if detailsRange:range( 2, 1 ):int() ~= 0 then
			-- Schema
			schema, remainingAfterSchema = parseSchema( type:int(), detailsRange:range( 3 ) )
		end

		local attributes, remainingAfterAttributes
		if remainingAfterSchema ~= nil and remainingAfterSchema:range( 0, 1 ):int() ~= 0 then
			-- Attributes
			attributes, remainingAfterAttributes = parseAttributes( type:int(), remainingAfterSchema:range( 1 ) )
		end

		return {
			range = typeRange,
			type = { type = type:int(), range = typeRange },
			schema = schema,
			attributes = attributes
		}, remainingAfterAttributes
	end
end

-- Package footer
master.parseTopicDetails = {
	parse = parseTopicDetails
}
diffusion = master
return master.parseTopicDetails
