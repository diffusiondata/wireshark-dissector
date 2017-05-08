
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

	local properties = {}
	local length = 0
	local propertyIndex = 1
	while propertyIndex <= numberOfProperties do
		local property = remaining:range( 0, 1 )
		local propertyValue = lengthPrefixedString( remaining:range( 1 ) )

		properties[propertyIndex] = {
			id = property,
			value = propertyValue
		}

		length = length + property:len() + propertyValue.fullRange:len()
		propertyIndex = propertyIndex + 1
		remaining = propertyValue.remaining
	end

	return {
		number = { range = numRange, number = numberOfProperties },
		properties = properties,
		rangeLength = numRange:len() + length
	}, remaining
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

	if type == diffusion.const.topicTypes.RECORD then
		local emptyValue = lengthPrefixedString( remainingAfterTopicProperties )

		parsedAttributes.emptyValue = emptyValue
		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength + emptyValue.fullRange:len()

		return parsedAttributes, emptyValue.remaining
	elseif type == diffusion.const.topicTypes.SLAVE then
		local masterTopic = lengthPrefixedString( remainingAfterTopicProperties )

		parsedAttributes.masterTopic = masterTopic
		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength + masterTopic.fullRange:len()

		return parsedAttributes, masterTopic.remaining
	elseif type == diffusion.const.topicTypes.ROUTING then
		local routingHandler = lengthPrefixedString( remainingAfterTopicProperties )

		parsedAttributes.routingHandler = routingHandler
		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength + routingHandler.fullRange:len()

		return parsedAttributes, routingHandler.remaining
	elseif type == diffusion.const.topicTypes.CUSTOM then
		local customHandler = lengthPrefixedString( remainingAfterTopicProperties )

		parsedAttributes.customHandler = customHandler
		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength + customHandler.fullRange:len()

		return parsedAttributes, customHandler.remaining
	elseif type == diffusion.const.topicTypes.TOPIC_NOTIFY then
		parsedAttributes.cachesMetadata = { range = remainingAfterTopicProperties:range( 0, 1 ) }
		parsedAttributes.rangeLength = 4 + topicProperties.rangeLength

		return parsedAttributes, remainingAfterTopicProperties:range( 1 )
	elseif type == diffusion.const.topicTypes.SERVICE then
		local serviceType = lengthPrefixedString( remainingAfterTopicProperties )
		local handler = lengthPrefixedString( serviceType.remaining )
		local requestTimeoutRange, remaining, requestTimeout = varint( handler.remaining )

		parsedAttributes.serviceType = serviceType
		parsedAttributes.serviceHandler = handler
		parsedAttributes.requestTimeout = { range = requestTimeoutRange, number = requestTimeout }
		parsedAttributes.rangeLength = 3 + topicProperties.rangeLength + serviceType.fullRange:len() + handler.fullRange:len() + requestTimeoutRange:len()

		return parsedAttributes, remaining
	elseif type == diffusion.const.topicTypes.PROTOCOL_BUFFER then
		parsedAttributes.updateMode = { range = remainingAfterTopicProperties:range( 0, 1 ) }
		parsedAttributes.deletionValue = lengthPrefixedString( remainingAfterTopicProperties:range( 1 ) )
		parsedAttributes.rangeLength = 4 + topicProperties.rangeLength + parsedAttributes.deletionValue.fullRange:len()

		return parsedAttributes, remainingAfterTopicProperties:range( 1 )
	elseif type == diffusion.const.topicTypes.PAGED_STRING then
		parsedAttributes.orderingPolicy = { range = remainingAfterTopicProperties:range( 0, 1 ) }

		local remaining
		if parsedAttributes.orderingPolicy.range:int() ~= diffusion.const.ordering.UNORDERED then
			parsedAttributes.duplicatesPolicy = { range = remainingAfterTopicProperties:range( 1, 1 ) }

			if parsedAttributes.orderingPolicy.range:int() == diffusion.const.ordering.DECLARED then
				parsedAttributes.order = { range = remainingAfterTopicProperties:range( 2, 1 ) }
				parsedAttributes.ruleType = { range = remainingAfterTopicProperties:range( 3, 1 ) }

				if parsedAttributes.ruleType.range:int() == diffusion.const.ruleType.COLLATION then
					parsedAttributes.rules = lengthPrefixedString( remainingAfterTopicProperties:range( 4 ) )
					remaining = parsedAttributes.rules.remaining
					parsedAttributes.rangeLength = 7 + topicProperties.rangeLength + parsedAttributes.rules.fullRange:len()
				else
					remaining = remainingAfterTopicProperties:range( 2 )
					parsedAttributes.rangeLength = 7 + topicProperties.rangeLength
				end
			else
				parsedAttributes.comparator = lengthPrefixedString( remainingAfterTopicProperties:range( 2 ) )
				parsedAttributes.rangeLength = 5 + topicProperties.rangeLength + parsedAttributes.comparator.fullRange:len()
				remaining = parsedAttributes.comparator.remaining
			end
		else
			parsedAttributes.rangeLength = 4 + topicProperties.rangeLength
			remaining = remainingAfterTopicProperties:range( 1 )
		end

		return parsedAttributes, remaining
	elseif type == diffusion.const.topicTypes.PAGED_RECORD then
		parsedAttributes.orderingPolicy = { range = remainingAfterTopicProperties:range( 0, 1 ) }

		local remaining
		if parsedAttributes.orderingPolicy.range:int() ~= diffusion.const.ordering.UNORDERED then
			parsedAttributes.duplicatesPolicy = { range = remainingAfterTopicProperties:range( 1, 1 ) }

			if parsedAttributes.orderingPolicy.range:int() == diffusion.const.ordering.DECLARED then
				local numRange, remainingOrderKeys, numberOfKeys = varint( remainingAfterTopicProperties:range( 2 ) )

				local orderKeys = {}
				local keysLength = 0
				local keyIndex = 1
				while keyIndex <= numberOfKeys do
					local fieldName = lengthPrefixedString( remainingOrderKeys )
					local order = { range = fieldName.remaining:range( 0, 1 ) }
					local ruleType = { range = fieldName.remaining:range( 1, 1 ) }

					local length = fieldName.fullRange:len() + 2
					local rules
					if ruleType.range:int() == diffusion.const.ruleType.COLLATION then
						rules = lengthPrefixedString( fieldName.remaining:range( 2 ) )
						remainingOrderKeys = rules.remaining
						length = length + rules.fullRange:len()
					else
						remainingOrderKeys = fieldName.remaining:range( 2 )
					end

					orderKeys[keyIndex] = {
						fieldName = fieldName,
						order = order,
						ruleType = ruleType,
						rules = rules,
						length = length
					}
					keysLength = keysLength + length
					keyIndex = keyIndex + 1
				end
				parsedAttributes.rangeLength = numRange:len() + keysLength
				parsedAttributes.orderKeys = orderKeys
				remaining = remainingOrderKeys
			else
				parsedAttributes.comparator = lengthPrefixedString( remainingAfterTopicProperties:range( 2 ) )
				parsedAttributes.rangeLength = 5 + topicProperties.rangeLength + parsedAttributes.comparator.fullRange:len()
				remaining = parsedAttributes.comparator.remaining
			end
		else
			parsedAttributes.rangeLength = 4 + topicProperties.rangeLength
			remaining = remainingAfterTopicProperties:range( 1 )
		end

		return parsedAttributes, remaining
	elseif type == diffusion.const.topicTypes.JSON or
		type == diffusion.const.topicTypes.BINARY or
		type == diffusion.const.topicTypes.STATELESS or
		type == diffusion.const.topicTypes.SINGLE_VALUE or
		type == diffusion.const.topicTypes.CHILD_LIST then

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
		type == diffusion.const.topicTypes.STATELESS or
		type == diffusion.const.topicTypes.SLAVE or
		type == diffusion.const.topicTypes.ROUTING or
		type == diffusion.const.topicTypes.CHILD_LIST or
		type == diffusion.const.topicTypes.TOPIC_NOTIFY or
		type == diffusion.const.topicTypes.SERVICE or
		type == diffusion.const.topicTypes.CUSTOM or
		type == diffusion.const.topicTypes.PAGED_STRING then

		return { rangeLength = 0 }, range
	elseif type == diffusion.const.topicTypes.SINGLE_VALUE or
		type == diffusion.const.topicTypes.RECORD or
		type == diffusion.const.topicTypes.PAGED_RECORD then

		local schema = lengthPrefixedString( range )
		return {
			schema = schema,
			rangeLength = schema.fullRange:len()
		}, schema.remaining
	elseif type == diffusion.const.topicTypes.PROTOCOL_BUFFER then

		local className = lengthPrefixedString( range )
		local messageName = lengthPrefixedString( className.remaining )
		return {
			className = className,
			messageName = messageName,
			rangeLength = className.fullRange:len() + messageName.fullRange:len()
		}, messageName.remaining
	else
		return {
			rangeLength = range:len()
		}
	end
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
			schema = schema.schema
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
