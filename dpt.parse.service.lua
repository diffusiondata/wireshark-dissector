
-- Parse package
-- This package provides reusable parsing utilities for individual elements of messages

-- Package header
local master = diffusion or {}
if master.parseService ~= nil then
	return master.parseService
end

local f_tcp_stream = diffusion.utilities.f_tcp_stream
local f_time_epoch = diffusion.utilities.f_time_epoch
local f_src_port = diffusion.utilities.f_src_port
local f_src_host = diffusion.utilities.f_src_host
local topicInfoTable = diffusion.info.topicInfoTable
local tcpConnections = diffusion.info.tcpConnections
local serviceMessageTable = diffusion.info.serviceMessageTable
local v5 = diffusion.v5
local varint = diffusion.parseCommon.varint
local lengthPrefixedString = diffusion.parseCommon.lengthPrefixedString
local lengthPrefixedBytes = diffusion.parseCommon.lengthPrefixedBytes
local parseVarSessionId = diffusion.parseCommon.parseVarSessionId
local parseTopicDetails = diffusion.parseTopicDetails.parse
local parseOptional = diffusion.parseCommon.parseOptional

local function parseSet( range, valueParser )
	local numRange, remaining, num = varint( range )

	local set = {}
	local length = 0
	local index = 1
	while index <= num do
		local value = valueParser( remaining )

		set[index] = value

		if value.fullRange ~= nil then
			length = length + value.fullRange:len()
		else
			length = length + value.range:len()
		end
		index = index + 1
		remaining = value.remaining
	end

	return {
		number = { range = numRange, number = num },
		set = set,
		rangeLength = numRange:len() + length
	}, remaining
end

local function parseMap( range, keyParser, valueParser )
	local numRange, remaining, num = varint( range )

	local map = {}
	local length = 0
	local index = 1
	while index <= num do
		local key = keyParser( remaining )
		local value = valueParser( key.remaining )

		map[index] = {
			key = key,
			value = value
		}

		length = length + key.fullRange:len() + value.fullRange:len()
		index = index + 1
		remaining = value.remaining
	end

	return {
		number = { range = numRange, number = num },
		map = map,
		rangeLength = numRange:len() + length,
		range = range:range( 0, numRange:len() + length )
	}, remaining
end

local function parseProperties( range )
	local map, remaining = parseMap(
		range,
		function ( r ) return lengthPrefixedString( r ) end,
		function ( r ) return lengthPrefixedString( r ) end
	)

	return {
		number = map.number,
		properties = map.map,
		rangeLength = map.rangeLength
	}, remaining
end

-- Parse a topic specifiation
local function parseTopicSpecification( range )
	local type = range:range( 0, 1 )

	local properties, remaining = parseProperties( range:range( 1 ) )
	return {
		type = { type = type:uint(), range = type },
		properties = properties
	}, remaining
end

local function parseTopicSpecificationInfo( range )
	local idRange, remaining, id = varint( range )
	local path = lengthPrefixedString( remaining )
	local specification = parseTopicSpecification( path.remaining )
	topicInfoTable:setInfo( f_tcp_stream(), id, path.range:string(), specification )

	return {
		range = range,
		id = { range = idRange, int = id },
		path = { range = path.fullRange, string = path.range:string() },
		specification = specification
	}
end

-- Parse a set of detail types
local function parseDetailTypeSet( range )
	local numberOfDetailTypes = range:range( 0, 1 ):uint()
	local set = { length = numberOfDetailTypes }
	for i = 0, numberOfDetailTypes - 1 do
		set[i] = range:range( 1 + i, 1 )
	end
	set.range = range:range( 0, numberOfDetailTypes + 1 )
	if range:range( 0, numberOfDetailTypes + 1 ):len() == range:len() then
		return set, range:range( 0, 0 )
	else
		return set, range:range( numberOfDetailTypes + 1 )
	end
end

-- Parse a client summary
local function parseSummary( range )
	local principal = lengthPrefixedString( range )
	local clientTypeRange = principal.remaining:range( 0, 1 )
	local transportTypeRange = principal.remaining:range( 1, 1 )
	return {
		principal = principal,
		clientType = clientTypeRange,
		transportType = transportTypeRange,
		range = range:range( 0, principal.fullRange:len() + 2 )
	}
end

-- Parse a client location
local function parseLocation( range )
	local length = 0
	local result = {}

	result.address = lengthPrefixedString( range )
	length = length + result.address.fullRange:len()

	result.hostName = lengthPrefixedString( result.address.remaining )
	length = length + result.hostName.fullRange:len()

	result.resolvedName = lengthPrefixedString( result.hostName.remaining )
	length = length + result.resolvedName.fullRange:len()

	result.addressType = result.resolvedName.remaining:range( 0, 1 )
	length = length + 1

	result.country = lengthPrefixedString( result.resolvedName.remaining:range( 1 ) )
	length = length + result.country.fullRange:len()

	result.language = lengthPrefixedString( result.country.remaining )
	length = length + result.language.fullRange:len()

	-- TODO: Turn these into floats
	local latitudeRange, longitudeR, latitude = varint( result.language.remaining )
	length = length + latitudeRange:len()

	local longitudeRange, remaining, longitude = varint( longitudeR )
	length = length + longitudeRange:len()

	result.remaining = remaining
	result.range = range( 0, length )
	return result
end

-- Parse session details
local function parseSessionDetails( range )
	local hasDetails = range:range( 0, 1 ):uint();
	if hasDetails == 0 then
		-- No details
		return {
			count = 0,
			range = range:range( 0, 1 )
		}
	end
	local result = {
		count = 0
	}
	local offset = 1

	parseOptional( range:range( offset ), function (tvb)
		result.count = result.count + 1
		result.summary = parseSummary( range:range( offset + 1 ) )
		offset = offset + result.summary.range:len() + 1
	end )

	parseOptional( range:range( offset ), function (tvb)
		result.count = result.count + 1
		result.location = parseLocation( range:range( offset + 1 ) )
		offset = offset + result.location.range:len() + 1
	end )

	parseOptional( range:range( offset ), function ( tvb )
		result.count = result.count + 1
		result.connector = lengthPrefixedString( range:range( offset + 1 ) )
		offset = offset + result.connector.fullRange:len() + 1
	end )

	parseOptional( range:range( offset ), function ( tvb )
		result.count = result.count + 1
		result.server = lengthPrefixedString( range:range( offset + 1 ) )
		offset = offset + result.server.fullRange:len() + 1
	end )

	result.range = range:range( 0, offset )
	if offset == range:len() then
		return result, range:range( 0, 0 )
	else
		return result, range:range( offset )
	end
end

-- Parse a session details listener notification event
local function parseSessionDetailsEvent( range )
	local result = {}
	result.sessionListenerEventTypeRange = range:range( 0, 1 )
	local eventType = result.sessionListenerEventTypeRange:uint()
	if eventType < 125 then
		result.closeReasonRange = result.sessionListenerEventTypeRange
	end
	local sessionId, sessionDetailsR = parseVarSessionId( range:range( 1 ) )
	result.sessionId = sessionId
	local sessionDetails, conversationR = parseSessionDetails( sessionDetailsR )
	result.sessionDetails = sessionDetails
	local cIdRange, remaining, cId = varint( conversationR )
	result.conversationId = { range = cIdRange, int = cId }
	return result
end

-- Parse a session listener registration
local function parseSessionDetailsListenerRegistrationRequest( range )
	return parseOptional( range:range( offset ), function ( tvb )
		local detailTypeSet, remaining = parseDetailTypeSet( tvb )
		local cIdRange, remaining, cId = varint( remaining )
		return { conversationId = { range = cIdRange, int = cId }, detailTypeSet = detailTypeSet }
	end, function ( tvb )
		local cIdRange, remaining, cId = varint( tvb )
		return { conversationId = { range = cIdRange, int = cId }, detailTypeSet = { range = range:range( 0, 1 ), length = 0 } }
	end )
end

-- Parse a session details lookup request
local function parseGetSessionDetailsRequest( range )
	local sessionId, detailTypeSetR = parseVarSessionId( range )
	local detailTypeSet = parseDetailTypeSet( detailTypeSetR )
	return {
		sessionId = sessionId,
		set = detailTypeSet
	}
end

-- Parse a set queue conflation request
local function parseSetClientQueueConflationRequest( range )
	local sessionId, conflateR = parseVarSessionId( range )
	local conflateEnabled = conflateR:range( 0 , 1 )
	return {
		sessionId = sessionId,
		conflateEnabledRange = conflateEnabled
	}
end

-- Parse a set queue throttler request
local function parseSetClientQueueThrottlerRequest( range )
	local sessionId, throttlerR = parseVarSessionId( range )
	local throttlerRange = throttlerR:range( 0 , 1 )
	local throttlerLimitRange, remaining, throttlerLimit = varint( throttlerR:range( 1 ) )
	return {
		sessionId = sessionId,
		throttlerRange = throttlerRange,
		limit = {
			range = throttlerLimitRange,
			int = throttlerLimit
		}
	}
end

local function parseCloseClient( range )
	local sessionId, reasonR = parseVarSessionId( range )
	local reason = lengthPrefixedString( reasonR )
	return {
		sessionId = sessionId,
		reason = reason
	}
end

local function parseControlRegistrationParameters( range )
	local serviceIdRange, remaining, serviceId = varint( range )
	local controlGroup = lengthPrefixedString( remaining )
	return {
		serviceId = { range = serviceIdRange, int = serviceId },
		controlGroup = controlGroup
	}, controlGroup.remaining
end

local function parseControlRegistrationRequest( range )
	local serviceIdRange, remaining, serviceId = varint( range )
	local controlGroup = lengthPrefixedString( remaining )
	local cIdRange, remaining, cId = varint( controlGroup.remaining )
	return {
		serviceId = { range = serviceIdRange, int = serviceId },
		controlGroup = controlGroup,
		conversationId = { range = cIdRange, int = cId }
	}, remaining
end

local function parseAuthenticationControlRegistrationRequest( range )
	local result, remaining = parseControlRegistrationParameters( range )
	local handlerName = lengthPrefixedString( remaining )
	return { controlRegInfo = result, handlerName = handlerName }
end

local function parseTopicControlRegistrationRequest( range )
	local result, remaining = parseControlRegistrationParameters( range )
	local topicPath = lengthPrefixedString( remaining )
	return { controlRegInfo = result, handlerTopicPath = topicPath }
end

local function parseUpdateSourceRegistrationRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	return { conversationId = { range = cIdRange, int = cId }, topicPath = topicPath }
end

local function parseContent( range )
	local encodingRange = range:range( 0, 1 )
	local lengthRange, remaining, length = varint( range:range( 1 ) )
	local bytesRange = remaining
	return {
		encoding = { range = encodingRange, int = encodingRange:int() },
		length = { range = lengthRange, int = length },
		bytes = { range = bytesRange }
	}
end

local function parseUpdate( range )
	local updateTypeRange = range:range( 0, 1 )
	local updateType = updateTypeRange:int()
	if updateType == 0x00 then
		local actionRange = range:range( 1, 1 )
		local content = parseContent( range:range( 2 ) )
		return {
			updateType = { range = updateTypeRange, int = updateType },
			updateAction = { range = actionRange, int = actionRange:int() },
			content = content
		}
	else
		return {
			updateType = { range = updateTypeRange, int = updateType }
		}
	end
end

local function parseUpdateSourceUpdateRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	local update = parseUpdate( topicPath.remaining )
	return { conversationId = { range = cIdRange, int = cId }, topicPath = topicPath, update = update }
end

local function parseNonExclusiveUpdateRequest( range )
	local topicPath = lengthPrefixedString( range )
	local update = parseUpdate( topicPath.remaining )
	return { topicPath = topicPath, update = update }
end

local function parseUpdateSourceStateRequest( range )
	local cIdRange, remaining, cId = varint( range )
	local oldStateByteRange = remaining:range( 0, 1 )
	local newStateByteRange = remaining:range( 1, 1 )
	return {
		conversationId = { range = cIdRange, int = cId },
		oldUpdateSourceState = { range = oldStateByteRange, int = oldStateByteRange:int() },
		newUpdateSourceState = { range = newStateByteRange, int = newStateByteRange:int() }
	}
end

local function parseSubscriptionNotification( range )
	local idRange, remaining, id = varint( range )
	local path = lengthPrefixedString( remaining )
	local topicDetails = parseTopicDetails( path.remaining )
	local tcpStream = f_tcp_stream()
	topicInfoTable:setInfo( tcpStream, id, path.range:string(), topicDetails )
	local topicInfo = {
		range = range,
		id = { range = idRange, int = id },
		path = { range = path.fullRange, string = path.range:string() },
		details = topicDetails
	}
	return topicInfo
end

local function parseUnsubscriptionNotification( range )
	local idRange, remaining, id = varint( range )
	local reasonRange, remaining, reason = varint( remaining )
	local tcpStream = f_tcp_stream()
	local topicName = topicInfoTable:getTopicPath( tcpStream, id )
	return {
		topic = { name = topicName, range = idRange },
		reason = { reason = reason, range = reasonRange }
	}
end

local function parseStatus( range )
	return { range = range }
end

local function parseUpdateSourceRegistrationResponse( range )
	local stateByteRange = range:range( 0, 1 )
	return { range = stateByteRange, int = stateByteRange:int() }
end

-- Parse add topic request
local function parseAddTopicRequest( range )
	local topicName = lengthPrefixedString( range )
	local referenceRange, remaining, reference = varint( topicName.remaining )
	local topicDetails, remaining = parseTopicDetails( remaining )
	local content
	if remaining ~= nil and remaining:range( 0, 1 ):int() == 1 then
		content = parseContent( remaining:range( 1 ) )
	end
	return {
		topicName = topicName,
		reference = {
			range = referenceRange,
			int = reference
		},
		topicDetails = topicDetails,
		content = content
	}
end

-- Parse add topic request
local function parseTopicAddRequest( range )
	local topicName = lengthPrefixedString( range )
	local specification = parseTopicSpecification( topicName.remaining )
	return {
		topicName = topicName,
		specification = specification
	}
end

local function parseUpdateTopicSet( range )
	local topicPath = lengthPrefixedString( range )
	local lengthRange, remaining, length = varint( topicPath.remaining )
	return {
		topicPath = topicPath,
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining
				}
			}
		}
	}
end

local function parseUpdateTopicDelta( range )
	local topicPath = lengthPrefixedString( range )
	local deltaTypeRange, remaining, deltaType = varint( topicPath.remaining )
	local lengthRange, remaining, length = varint( remaining )
	return {
		topicPath = topicPath,
		update = {
			deltaType = {
				range = deltaTypeRange,
				int = deltaType
			},
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining
				}
			}
		}
	}
end

local function parseUpdateSourceSet( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	local lengthRange, remaining, length = varint( topicPath.remaining )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		topicPath = topicPath,
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining
				}
			}
		}
	}
end

local function parseUpdateSourceDelta( range )
	local cIdRange, remaining, cId = varint( range )
	local topicPath = lengthPrefixedString( remaining )
	local deltaTypeRange, remainingUpdate, deltaType = varint( topicPath.remaining )
	local lengthRange, remaining, length = varint( remainingUpdate )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		topicPath = topicPath,
		update = {
			deltaType = {
				range = deltaTypeRange,
				int = deltaType
			},
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining
				}
			}
		}
	}
end

local function parseMessagingSend( range )
	local path = lengthPrefixedString( range )
	local dataType = lengthPrefixedString( path.remaining )
	local lengthRange, bytesRange, length = varint( dataType.remaining )
	return {
		path = path,
		dataType = dataType,
		bytes = {
			length = {
				range = lengthRange,
				length = length
			},
			range = bytesRange
		}
	}
end

local function parseMessagingSendToSession( range )
	local cIdRange, remaining, cId = varint( range )
	local sessionId, remaining = parseVarSessionId( remaining )
	local path = lengthPrefixedString( remaining )
	local properties, remaining = parseProperties( path.remaining )
	local dataType = lengthPrefixedString( remaining )
	local lengthRange, bytesRange, length = varint( dataType.remaining )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		sessionId = sessionId,
		path = path,
		dataType = dataType,
		bytes = {
			length = {
				range = lengthRange,
				length = length
			},
			range = bytesRange
		}
	}
end

local function parseMessagingResponse( range )
	local dataType = lengthPrefixedString( range )
	local lengthRange, bytesRange, length = varint( dataType.remaining )
	return {
		dataType = dataType,
		bytes = {
			length = {
				range = lengthRange,
				length = length
			},
			range = bytesRange
		}
	}
end

local function parseRequestControlRegistration( range )
	local result, remaining = parseControlRegistrationParameters( range )
	local path = lengthPrefixedString( remaining )

	local numPropertiesRange, remaining, numProperties = varint( path.remaining )

	local properties = {}
	local length = 0
	local propertyIndex = 1
	while propertyIndex <= numProperties do
		local propertyKey = lengthPrefixedString( remaining )

		properties[propertyIndex] = {
			key = propertyKey
		}

		length = length + propertyKey.fullRange:len()
		propertyIndex = propertyIndex + 1
		remaining = propertyKey.remaining
	end

	return {
		controlRegInfo = result,
		handlerPath = path,
		number = { range = numPropertiesRange, number = numProperties },
		properties = properties,
		rangeLength = numPropertiesRange:len() + length
	}
end

local function parseForwardRequest( range )
	local sessionId, remaining = parseVarSessionId( range )
	local path = lengthPrefixedString( remaining )
	local dataType = lengthPrefixedString( path.remaining )
	local lengthRange, bytesRange, length = varint( dataType.remaining )
	return {
		sessionId = sessionId,
		path = path,
		dataType = dataType,
		bytes = {
			length = {
				range = lengthRange,
				length = length
			},
			range = bytesRange
		}
	}
end

local function parseTopicNotificationSelection( range )
	local cIdRange, remaining, cId = varint( range )
	local path = lengthPrefixedString( remaining )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		path = path
	}
end

local function parseTopicNotificationEvent( range )
	local cIdRange, remaining, cId = varint( range )
	local path = lengthPrefixedString( remaining )
	local typeByteRange = path.remaining:range( 0, 1 )
	local specification = parseTopicSpecification( path.remaining:range( 1 ) )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		path = path,
		type = typeByteRange,
		specification = specification
	}
end

local function parseTopicNotificationDescendantEvent( range )
	local cIdRange, remaining, cId = varint( range )
	local path = lengthPrefixedString( remaining )
	local typeByteRange = path.remaining:range( 0, 1 )
	return {
		conversationId = {
			range = cIdRange,
			int = cId
		},
		path = path,
		type = typeByteRange
	}
end

local function parseUpdateResult( range )
	local resultByteRange = range:range( 0, 1 )
	return { range = resultByteRange, int = resultByteRange:int() }
end

local function parseAddResult( range )
	local resultByteRange = range:range( 0, 1 )
	return { range = resultByteRange, int = resultByteRange:int() }
end

local function parseSessionLockAcquisition( range )
		local lockName = lengthPrefixedString( range )
		local idRange, remaining, id = varint( lockName.remaining )
		local scopeByteRange = remaining:range( 0, 1 )
		return {
			lockName = lockName,
			id = { range = idRange, int = id },
			scope = scopeByteRange
		}
end

local function parseSessionLockCancellation( range )
		local lockName = lengthPrefixedString( range )
		local idRange, remaining, id = varint( lockName.remaining )
		return {
			lockName = lockName,
			id = { range = idRange, int = id },
			fullRange = range( 0, lockName.fullRange:len() + idRange:len() )
		}, remaining
end

local function parseConstraint( range )
	local type = range:range( 0, 1 )
	local result = {
		type = type,
	}

	local typeId = type:uint()
	if typeId == 1 then
		local constraints, r = parseSet(
			range:range( 1 ),
			function ( n ) return parseConstraint( n ) end
		)
		result.constraints = constraints
		result.remaining = r
		result.range = range:range( 0, range:len() - r:len() )
	elseif typeId == 2 then
		result.content = lengthPrefixedBytes( range:range( 1 ) )
		result.remaining = result.content.remaining
		result.range = range:range( 0, 1 + result.content.fullRange:len() )
	elseif typeId == 4 then
		local lock, remaining = parseSessionLockCancellation( range:range( 1 ) )
		result.lock = lock
		result.remaining = remaining
		result.range = range:range( 0, 1 + result.lock.fullRange:len() )
	elseif typeId == 6 then
		local with, remaining = parseMap(
			range:range( 1 ),
			function (r) return lengthPrefixedString(r) end,
			function (r) return lengthPrefixedBytes(r) end
		)
		local without, r = parseSet(
			remaining,
			function (r) return lengthPrefixedString(r) end
		)
		result.with = with
		result.without = without
		result.remaining = r
		result.range = range:range( 0, 1 + result.with.rangeLength + result.without.rangeLength )
	elseif range:len() > 1 then
		result.remaining = range:range( 1 )
		result.range = range:range( 0, 1 )
	else
		result.remaining = range:range( 0, 0 )
		result.range = range:range( 0, 1 )
	end

	return result
end

local function parseTopicSetRequest( range )
	local topicPath = lengthPrefixedString( range )
	local type = topicPath.remaining:range( 0, 1 )
	local lengthRange, remaining, length = varint( topicPath.remaining:range( 1 ) )
	local constraint = parseConstraint( remaining:range( length ) )

	return {
		topicPath = topicPath,
		type = { type = type:uint(), range = type },
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining:range( 0, length )
				}
			}
		},
		constraint = constraint
	}
end

local function parseTopicAndAndSetRequest( range )
	local topicPath = lengthPrefixedString( range )
	local specification, r = parseTopicSpecification( topicPath.remaining )
	local lengthRange, remaining, length = varint( r )
	local constraint = parseConstraint( remaining:range( length ) )

	return {
		topicPath = topicPath,
		specification = specification,
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining:range( 0, length )
				}
			}
		},
		constraint = constraint
	}
end

local function parseCreateUpdateStreamRequest( range )
	local topicPath = lengthPrefixedString( range )
	local type = topicPath.remaining:range( 0, 1 )
	local constraint = parseConstraint( topicPath.remaining:range( 1 ) )

	return {
		topicPath = topicPath,
		type = { type = type:uint(), range = type },
		constraint = constraint
	}
end

local function parseCreateUpdateStreamAndSetRequest( range )
	local topicPath = lengthPrefixedString( range )
	local type = topicPath.remaining:range( 0, 1 )
	local lengthRange, remaining, length = varint( topicPath.remaining:range( 1 ) )
	local constraint = parseConstraint( remaining:range( length ) )

	return {
		topicPath = topicPath,
		type = { type = type:uint(), range = type },
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining:range( 0, length )
				}
			}
		},
		constraint = constraint
	}
end

local function parseStreamAddTopicRequest( range )
	local topicPath = lengthPrefixedString( range )
	local specification, r = parseTopicSpecification( topicPath.remaining )
	local constraint = parseConstraint( r )

	return {
		topicPath = topicPath,
		specification = specification,
		constraint = constraint
	}
end

local function parseStreamAddAndSetTopicRequest( range )
	local topicPath = lengthPrefixedString( range )
	local specification, r = parseTopicSpecification( topicPath.remaining )
	local lengthRange, remaining, length = varint( r )
	local constraint = parseConstraint( remaining:range( length ) )

	return {
		topicPath = topicPath,
		specification = specification,
		update = {
			content = {
				length = {
					range = lengthRange,
					int = length
				},
				bytes = {
					range = remaining:range( 0, length )
				}
			}
		},
		constraint = constraint
	}
end

local function parseServiceRequest( serviceBodyRange, service, conversation, result )
	local tcpStream = f_tcp_stream()
	local session = tcpConnections[tcpStream]
	-- Store the request so the response time can be calculated
	local isClient = session.client:matches( f_src_host(), f_src_port() )
	if isClient then
		-- Request is from the client so the client created the conversation Id
		serviceMessageTable:addRequest( tcpStream, session.client, conversation, f_time_epoch() )
	else
		-- Request is from the server so the server created the conversation Id
		serviceMessageTable:addRequest( tcpStream, session.server, conversation, f_time_epoch() )
	end

	-- Parse the request for service specific information
	if service == v5.SERVICE_FETCH then
		local selector = lengthPrefixedString( serviceBodyRange )
		result.selector = { range = selector.fullRange, string = selector.string }
	elseif service == v5.SERVICE_SUBSCRIBE then
		local selector = lengthPrefixedString( serviceBodyRange )
		result.selector = { range = selector.fullRange, string = selector.string }
	elseif service == v5.SERVICE_UNSUBSCRIBE then
		local selector = lengthPrefixedString( serviceBodyRange )
		result.selector = { range = selector.fullRange, string = selector.string }
	elseif service == v5.SERVICE_ADD_TOPIC then
		local info = parseAddTopicRequest( serviceBodyRange )
		result.addTopic = info
	elseif service == v5.SERVICE_TOPIC_ADD then
		local info = parseTopicAddRequest( serviceBodyRange )
		result.topicAdd = info
	elseif service == v5.SERVICE_REMOVE_TOPICS then
		local selector = lengthPrefixedString( serviceBodyRange )
		result.selector = { range = selector.fullRange, string = selector.string }
	elseif service == v5.SERVICE_SUBSCRIPTION_NOTIFICATION then
		result.topicInfo = parseSubscriptionNotification( serviceBodyRange )
	elseif service == v5.SERVICE_NOTIFY_SUBSCRIPTION then
		result.topicSpecInfo = parseTopicSpecificationInfo( serviceBodyRange )
	elseif service == v5.SERVICE_UNSUBSCRIPTION_NOTIFICATION then
		result.topicUnsubscriptionInfo = parseUnsubscriptionNotification( serviceBodyRange )
	elseif service == v5.SERVICE_AUTHENTICATION_CONTROL_REGISTRATION then
		local info = parseAuthenticationControlRegistrationRequest( serviceBodyRange )
		result.controlRegInfo = info.controlRegInfo
		result.handlerName = info.handlerName
	elseif service == v5.SERVICE_TOPIC_CONTROL_REGISTRATION then
		local info = parseTopicControlRegistrationRequest( serviceBodyRange )
		result.controlRegInfo = info.controlRegInfo
		result.handlerTopicPath = info.handlerTopicPath
	elseif service == v5.SERVICE_SERVER_CONTROL_REGISTRATION then
		local info = parseControlRegistrationRequest( serviceBodyRange )
		result.controlRegInfo = info
	elseif service == v5.SERVICE_UPDATE_SOURCE_REGISTRATION then
		local info = parseUpdateSourceRegistrationRequest( serviceBodyRange )
		result.updateSourceInfo = info
	elseif service == v5.SERVICE_UPDATE_SOURCE_UPDATE then
		local info = parseUpdateSourceUpdateRequest( serviceBodyRange )
		result.updateInfo = info
	elseif service == v5.SERVICE_UPDATE_SOURCE_STATE then
		local info = parseUpdateSourceStateRequest( serviceBodyRange )
		result.updateSourceInfo = info
	elseif service == v5.SERVICE_UPDATE_TOPIC then
		local info = parseNonExclusiveUpdateRequest( serviceBodyRange );
		result.updateInfo = info
	elseif service == v5.SERVICE_SESSION_LISTENER_REGISTRATION then
		result.sessionListenerRegInfo = parseSessionDetailsListenerRegistrationRequest( serviceBodyRange );
	elseif service == v5.SERVICE_SESSION_DETAILS_EVENT then
		result.sessionListenerEventInfo = parseSessionDetailsEvent( serviceBodyRange )
	elseif service == v5.SERVICE_GET_SESSION_DETAILS then
		result.lookupSessionDetailsRequest = parseGetSessionDetailsRequest( serviceBodyRange )
	elseif service == v5.SERVICE_SET_CLIENT_QUEUE_CONFLATION then
		result.clientQueueConflationInfo = parseSetClientQueueConflationRequest( serviceBodyRange )
	elseif service == v5.SERVICE_THROTTLE_CLIENT_QUEUE then
		result.clientThrottlerInfo = parseSetClientQueueThrottlerRequest( serviceBodyRange )
	elseif service == v5.SERVICE_SERVER_CONTROL_DEREGISTRATION then
		result.controlDeregInfo = parseControlRegistrationParameters( serviceBodyRange )
	elseif service == v5.SERVICE_CLOSE_CLIENT then
		result.closeClientInfo = parseCloseClient( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_TOPIC_SET then
		result.updateInfo = parseUpdateTopicSet( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_TOPIC_DELTA then
		result.updateInfo = parseUpdateTopicDelta( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_SOURCE_SET then
		result.updateInfo = parseUpdateSourceSet( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_SOURCE_DELTA then
		result.updateInfo = parseUpdateSourceDelta( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_SOURCE_DEREGISTRATION then
		local conversationRange, remaining, conversationId = varint( serviceBodyRange )
		result.updateSourceInfo = {
			conversationId = {
				range = conversationRange,
				int = conversationId
			}
		}
	elseif service == v5.SERVICE_MESSAGING_SEND then
		result.send = parseMessagingSend( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_RECEIVER_CLIENT then
		result.sendToSession = parseMessagingSendToSession( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_RECEIVER_CONTROL_REGISTRATION then
		result.requestControlRegistration = parseRequestControlRegistration( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_RECEIVER_SERVER then
		result.forwardRequest = parseForwardRequest( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_NOTIFICATION_SELECTION then
		result.notificationSelection = parseTopicNotificationSelection( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_NOTIFICATION_DESELECTION then
		result.notificationSelection = parseTopicNotificationSelection( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_NOTIFICATION_EVENTS then
		result.notificationEvent = parseTopicNotificationEvent( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_DESCENDANT_EVENTS then
		result.notificationEvent = parseTopicNotificationDescendantEvent( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_NOTIFICATION_DEREGISTRATION then
		local conversationRange, remaining, conversationId = varint( serviceBodyRange )
		result.notificationDereg = {
			conversationId = {
				range = conversationRange,
				int = conversationId
			}
		}
	elseif service == v5.SERVICE_ACQUIRE_SESSION_LOCK then
		result.sessionLockRequest = parseSessionLockAcquisition( serviceBodyRange )
	elseif service == v5.SERVICE_CANCEL_ACQUIRE_SESSION_LOCK then
		result.sessionLockCancellation = parseSessionLockCancellation( serviceBodyRange )
	elseif service == v5.SERVICE_RELEASE_SESSION_LOCK then
		result.sessionLockAcquisition = parseSessionLockAcquisition( serviceBodyRange )
	elseif service == v5.SERVICE_SET_TOPIC then
		result.updateInfo = parseTopicSetRequest( serviceBodyRange )
	elseif service == v5.SERVICE_ADD_AND_SET_TOPIC then
		result.updateInfo = parseTopicAndAndSetRequest( serviceBodyRange )
	elseif service == v5.SERVICE_CREATE_UPDATE_STREAM then
		result.updateInfo = parseCreateUpdateStreamRequest( serviceBodyRange )
	elseif service == v5.SERVICE_CREATE_UPDATE_STREAM_AND_SET then
		result.updateInfo = parseCreateUpdateStreamAndSetRequest( serviceBodyRange )
	elseif service == v5.SERVICE_STREAM_ADD_TOPIC then
		result.updateInfo = parseStreamAddTopicRequest( serviceBodyRange )
	elseif service == v5.SERVICE_STREAM_ADD_AND_SET_TOPIC then
		result.updateInfo = parseStreamAddAndSetTopicRequest( serviceBodyRange )
	end
	return result
end

local function parseServiceResponse( serviceBodyRange, service, conversation, result )
	-- Parse the response for service specific information
	if service == v5.SERVICE_UPDATE_SOURCE_REGISTRATION then
		local info = parseUpdateSourceRegistrationResponse( serviceBodyRange )
		result.updateSourceInfo = {
			newUpdateSourceState = info
		}
	elseif service == v5.SERVICE_GET_SESSION_DETAILS then
		result.lookupSessionDetailsResponse = parseSessionDetails( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_TOPIC_SET then
		result.updateResult = parseUpdateResult( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_TOPIC_DELTA then
		result.updateResult = parseUpdateResult( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_SOURCE_SET then
		result.updateResult = parseUpdateResult( serviceBodyRange )
	elseif service == v5.SERVICE_UPDATE_SOURCE_DELTA then
		result.updateResult = parseUpdateResult( serviceBodyRange )
	elseif service == v5.SERVICE_TOPIC_ADD then
		result.addResult = parseAddResult( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_RECEIVER_CLIENT then
		result.requestResponse = parseMessagingResponse( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_SEND then
		result.requestResponse = parseMessagingResponse( serviceBodyRange )
	elseif service == v5.SERVICE_MESSAGING_RECEIVER_SERVER then
		result.requestResponse = parseMessagingResponse( serviceBodyRange )
	elseif service == v5.SERVICE_ACQUIRE_SESSION_LOCK then
		result.sessionLockAcquisition = parseSessionLockAcquisition( serviceBodyRange )
	elseif service == v5.SERVICE_RELEASE_SESSION_LOCK then
		result.sessionLockReleased = serviceBodyRange:range( 0, 1 )
	end

	-- Calculate the response time
	local reqTime
	local tcpStream = f_tcp_stream()
	local session = tcpConnections[tcpStream]
	local isClient = session.client:matches( f_src_host(), f_src_port() )
	if isClient then
		-- Response is from the client so the server created the conversation Id
		reqTime = serviceMessageTable:getRequestTime( tcpStream, session.server, conversation )
	else
		-- Response is from the server so the client created the conversation Id
		reqTime = serviceMessageTable:getRequestTime( tcpStream, session.client, conversation )
	end
	result.responseTime = tostring( f_time_epoch() - reqTime )

	return result
end

local function parseServiceError( serviceBodyRange, service, conversation, result )
	local errorMessage = lengthPrefixedString( serviceBodyRange )
	local codeRange, remaining, code = varint( errorMessage.remaining )

	result.error = {
		errorMessage = errorMessage,
		errorCode = {
			range = codeRange,
			code = code
		}
	}

	-- Calculate the response time
	local reqTime
	local tcpStream = f_tcp_stream()
	local session = tcpConnections[tcpStream]
	local isClient = session.client:matches( f_src_host(), f_src_port() )
	if isClient then
		-- Response is from the client so the server created the conversation Id
		reqTime = serviceMessageTable:getRequestTime( tcpStream, session.server, conversation )
	else
		-- Response is from the server so the client created the conversation Id
		reqTime = serviceMessageTable:getRequestTime( tcpStream, session.client, conversation )
	end
	result.responseTime = tostring( f_time_epoch() - reqTime )

	return result
end

-- Parse the message as a service request or response
local function parseAsV4ServiceMessage( range )
	if range ~= nil and range:len() >= 2 then
		-- Parse service header
		local serviceRange, modeR, service = varint( range )
		local modeRange, conversationR, mode = varint( modeR )
		local conversationRange, serviceBodyRange, conversation = varint( conversationR )
		-- Get values for service node
		local serviceNodeRange = range

		local result = { range = serviceNodeRange, id = { range = serviceRange, int = service },
			mode = { range = modeRange, int = mode },
			conversation = { range = conversationRange, int = conversation },
			body = serviceBodyRange }

		if mode == v5.MODE_REQUEST then
			return parseServiceRequest( serviceBodyRange, service, conversation, result )
		elseif mode == v5.MODE_RESPONSE then
			return parseServiceResponse( serviceBodyRange, service, conversation, result )
		else
			return result
		end
	else
		return {}
	end
end

local function parseAsV59ServiceMessage( modeRange, range )

	if range ~= nil and range:len() >= 2 then
		-- Parse service header
		local serviceRange, conversationAndBodyRange, service = varint( range )
		local conversationRange, serviceBodyRange, conversation = varint( conversationAndBodyRange )
		local mode = modeRange:uint()
		-- Get values for service node
		local serviceNodeRange = range

		local result = { range = serviceNodeRange, id = { range = serviceRange, int = service },
			mode = { range = modeRange, int = mode },
			conversation = { range = conversationRange, int = conversation },
			body = serviceBodyRange }

		if mode == v5.P9_MODE_REQUEST then
			return parseServiceRequest( serviceBodyRange, service, conversation, result )
		elseif mode == v5.P9_MODE_RESPONSE then
			return parseServiceResponse( serviceBodyRange, service, conversation, result )
		elseif mode == v5.P9_MODE_ERROR then
			return parseServiceError( serviceBodyRange, service, conversation, result )
		else
			return result
		end
	else
		return {}
	end
end

-- Package footer
master.parseService = {
	parseAsV4ServiceMessage = parseAsV4ServiceMessage,
	parseAsV59ServiceMessage = parseAsV59ServiceMessage
}
diffusion = master
return master.parseService
