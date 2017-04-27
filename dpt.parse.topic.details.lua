
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
			number = { range = numRange, number = numberOfProperties },
			rangeLength = 1
		}, remaining
	end
	return {
		number = { range = numRange, number = numberOfProperties },
		rangeLength = range:len()
	}, nil
end

local function parseAttributes( type, range )
	local autoSubscribe = range( 0, 1 )
	local tidiesOnUnsubscribe = range( 1, 1 )
	local reference = lengthPrefixedString( range( 2 ) )
	local topicProperties, remainingAfterTopicProperties = parseTopicProperties( reference.remaining )

	local parsedAttributes = {
		autoSubscribe = autoSubscribe,
		tidiesOnUnsubscribe = tidiesOnUnsubscribe,
		reference = reference,
		topicProperties = topicProperties
	}

	-- Currently only Universal topic details are fully parsed
	if type == diffusion.const.topicTypes.JSON or
		type == diffusion.const.topicTypes.BINARY or
		type == diffusion.const.topicTypes.STATELESS then

		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength
		return parsedAttributes, remainingAfterTopicProperties
	else
		parsedAttributes.rangeLength = range:len()
		return parsedAttributes, remainingAfterTopicProperties
	end
end

local function parseSchema( type, range )
	if type == diffusion.const.topicTypes.JSON or
		type == diffusion.const.topicTypes.BINARY or
		type == diffusion.const.topicTypes.STATELESS then

		return { rangeLength = 0 }, range
	end
	return {
		rangeLength = range:len()
	}
end

local function parseTopicDetails( detailsRange )
	local any = detailsRange:range( 0, 1 )
	if any:int() == 0 then
		return { range = any, level = "NONE", type = { type = diffusion.const.topicTypes.NONE, range = any } }
	else
		local type = detailsRange:range( 1, 1 )
		local typeRange = detailsRange:range( 0, 2 )
		local level = "BASIC"
		local rangeLength = 3

		local schema, remainingAfterSchema
		if detailsRange:range( 2, 1 ):int() ~= 0 then
			level = "SCHEMA"
			schema, remainingAfterSchema = parseSchema( type:int(), detailsRange:range( 3 ) )
			rangeLength = rangeLength + schema.rangeLength
		end

		local attributes, remainingAfterAttributes
		if remainingAfterSchema ~= nil and remainingAfterSchema:range( 0, 1 ):int() ~= 0 then
			level = "FULL"
			attributes, remainingAfterAttributes = parseAttributes( type:int(), remainingAfterSchema:range( 1 ) )
			rangeLength = rangeLength + attributes.rangeLength + 1
		end

		return {
			range = detailsRange:range( 0, rangeLength ),
			level = level,
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
