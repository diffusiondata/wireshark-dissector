
-- Proto package
-- This package sets up the protocol description, fields and value mappings used by Wireshark.

-- Package header
local master = diffusion or {}
if master.proto ~= nil then
	return master.proto
end

local v5 = diffusion.v5

local dptProto = Proto( "DPT", "Diffusion Protocol")

-- Connection negotiation fields
dptProto.fields.connectionMagicNumber = ProtoField.uint8( "dpt.connection.magicNumber", "Magic number" , base.HEX )
dptProto.fields.connectionProtoNumber = ProtoField.uint8( "dpt.connection.protocolVersion", "Protocol version" )
dptProto.fields.connectionType = ProtoField.uint8( "dpt.connection.connectionType", "Connection Type", base.HEX, master.const.clientTypesByValue )
dptProto.fields.capabilities = ProtoField.uint8( "dpt.connection.capabilities", "Client Capabilities", base.HEX, master.const.capabilities )
dptProto.fields.connectionResponse = ProtoField.uint8( "dpt.connection.responseCode", "Connection Response", base.DEC, master.const.responseCodes )
dptProto.fields.clientID = ProtoField.string( "dpt.clientID", "Client ID" )
dptProto.fields.direction = ProtoField.string( "dpt.direction", "Direction" )
dptProto.fields.wsConnectionProtoNumber= ProtoField.string( "dpt.ws.connection.protocolVersion", "Protocol version" )
dptProto.fields.wsConnectionType = ProtoField.string( "dpt.ws.connection.connectionType", "Connection Type" )
dptProto.fields.wsPrincipal = ProtoField.string( "dpt.ws.connection.principal", "Principal")
dptProto.fields.wsCredentials = ProtoField.string( "dpt.ws.connection.credentials", "Credentials")
dptProto.fields.sessionId = ProtoField.string( "dpt.connection.sessionId", "Session Id")
dptProto.fields.sessionToken = ProtoField.string( "dpt.connection.sessionToken", "Session Token")
dptProto.fields.reconnectionTimeout = ProtoField.uint32( "dpt.connection.reconnectionTimeout", "Reconnection timeout", base.DEC )
dptProto.fields.pingPeriod = ProtoField.uint64( "dpt.connection.pingPeriod", "System ping period", base.DEC )

-- Message fields
dptProto.fields.typeHdr = ProtoField.uint8( "dpt.message.type", "Type", base.HEX ) -- no lookup table possible here, it's a bitfield
dptProto.fields.encodingHdr = ProtoField.uint8( "dpt.message.encoding", "Encoding", base.HEX, master.const.encodingTypesByValue )
dptProto.fields.topic = ProtoField.string( "dpt.header.topic", "Topic" )
dptProto.fields.alias = ProtoField.string( "dpt.header.alias", "Alias" )
dptProto.fields.headers = ProtoField.string( "dptProto.headers", "Headers" )
dptProto.fields.userHeaders = ProtoField.string( "dptProto.userHeaders", "User headers" )
dptProto.fields.fixedHeaders = ProtoField.string( "dptProto.fixedHeaders", "Fixed headers" )
dptProto.fields.content = ProtoField.bytes( "dptProto.content", "Content" )
dptProto.fields.connection = ProtoField.string( "dptProto.connection", "Connection" )
dptProto.fields.sizeHdr = ProtoField.uint32( "dptProto.size", "Size" )
dptProto.fields.messageLengthSize = ProtoField.uint8( "dptProto.messageLengthSize", "Size Length", base.DEC )

dptProto.fields.record = ProtoField.string( "dpt.records" )
dptProto.fields.field = ProtoField.string( "dpt.fields" )

-- Command message fields
dptProto.fields.command =  ProtoField.string( "dpt.header.command", "Command" )
dptProto.fields.commandTopicType = ProtoField.string( "dpt.header.command.topicType", "Topic Type" )
dptProto.fields.commandTopicCategory = ProtoField.string( "dpt.header.command.topicCategory", "Topic Category" )
dptProto.fields.notificationType = ProtoField.string( "dpt.header.command.notificationType", "Notification Type" )
dptProto.fields.parameters = ProtoField.string( "dptProto.field.parameters", "Parameters" )

dptProto.fields.loginCreds = ProtoField.string( "dptProto.field.loginCreds", "Login Credentials" )
dptProto.fields.loginTopics = ProtoField.string( "dptProto.field.loginTopics", "Subscriptions" )

-- Ping message fields
dptProto.fields.timestamp = ProtoField.string( "dpt.header.timestamp", "Timestamp" )
dptProto.fields.queueSize = ProtoField.string( "dpt.header.queueSize", "Message Queue size" )

-- Ack message field
dptProto.fields.ackId = ProtoField.string( "dpt.header.ackId", "Acknowledgement ID" )

-- Service fields
dptProto.fields.service = ProtoField.string( "dpt.service", "Service" )
dptProto.fields.serviceIdentity = ProtoField.uint8( "dpt.service.identity", "Service Identity", base.HEX, v5.serviceIdentity )
dptProto.fields.serviceMode = ProtoField.uint8( "dpt.service.mode", "Mode", base.HEX, v5.modeValues )
dptProto.fields.serviceModeP9 = ProtoField.uint8( "dpt.service.mode.p9", "Mode", base.HEX, v5.p9ModeValues )
dptProto.fields.conversation = ProtoField.uint32( "dpt.conversation.id", "Conversation ID" )
dptProto.fields.topicInfo = ProtoField.string( "dpt.service.topicInfo", "Topic Info" )
dptProto.fields.topicId = ProtoField.uint32( "dpt.service.topicInfo.topicId", "Topic ID" )
dptProto.fields.topicPath = ProtoField.string( "dpt.service.topicInfo.topicPath", "Topic Path" )
dptProto.fields.topicType = ProtoField.uint8( "dpt.service.topicInfo.topicType", "Topic Type", base.HEX, diffusion.const.topicTypes.byByte )
dptProto.fields.selector = ProtoField.string( "dpt.service.selector", "Topic selector" )
dptProto.fields.status = ProtoField.uint8( "dpt.service.status", "Status", base.HEX, master.const.statusResponseBytes )
dptProto.fields.topicName = ProtoField.string( "dpt.service.topicName", "Topic Name" )
dptProto.fields.topicUnSubReason = ProtoField.uint8( "dpt.service.topicUnsubscribeReason", "Reason", base.HEX, master.const.topicRemovalReasonByBytes )
dptProto.fields.responseTime = ProtoField.string( "dpt.service.responseTime", "Response time" )
dptProto.fields.handlerName = ProtoField.string( "dpt.service.handlerName", "Handler name" )
dptProto.fields.controlGroup = ProtoField.string( "dpt.service.controlGroup", "Control group" )
dptProto.fields.regServiceId = ProtoField.uint8( "dpt.service.regServiceId", "Registration Service Identity", base.HEX, v5.serviceIdentity )
dptProto.fields.handlerTopicPath = ProtoField.string( "dpt.service.handlerTopicPath", "Handler topic path" )
dptProto.fields.errorMessage = ProtoField.string( "dpt.service.error.message", "Error message" )
dptProto.fields.reasonCode = ProtoField.uint8( "dpt.service.error.code", "Error reason code" )
dptProto.fields.path = ProtoField.string( "dpt.service.path", "Path" )
dptProto.fields.dataType = ProtoField.string( "dpt.service.dataType", "Data Type" )
dptProto.fields.requestId = ProtoField.uint32( "dpt.service.requestId", "Conversation ID (request)" )
dptProto.fields.sessionPropertiesNumber = ProtoField.uint32( "dpt.session.properties.number", "Session properties" )
dptProto.fields.sessionPropertyKey = ProtoField.string( "dpt.session.property.key", "Key" )

-- Session lock fields
dptProto.fields.lockName = ProtoField.string( "dpt.service.lock.name", "Lock name" )
dptProto.fields.lockRequestId = ProtoField.uint32( "dpt.service.lock.request.id", "Request ID" )
dptProto.fields.lockScope = ProtoField.uint8( "dpt.service.lock.scope", "Scope", base.HEX, master.const.lockScopeByBytes )

-- Update topic
dptProto.fields.updateSourceTopicPath = ProtoField.string( "dpt.service.updateSourceTopicPath", "Update source topic path" )
dptProto.fields.oldUpdateSourceState = ProtoField.uint8( "dpt.service.updateSourceState.old", "Old update source state", base.HEX, master.const.updateSourceStateByBytes )
dptProto.fields.newUpdateSourceState = ProtoField.uint8( "dpt.service.updateSourceState", "New update source state", base.HEX, master.const.updateSourceStateByBytes )
dptProto.fields.updateType = ProtoField.uint8( "dpt.service.updateType", "Update type", base.HEX, master.const.updateTypeByBytes )
dptProto.fields.updateAction = ProtoField.uint8( "dpt.service.updateAction", "Update action", base.HEX, master.const.updateActionByBytes )
dptProto.fields.contentLength = ProtoField.uint32( "dptProto.content.length", "Content length", base.DEC )
dptProto.fields.deltaType = ProtoField.uint8( "dpt.service.deltaType", "Delta type", base.HEX, master.const.deltaType )
dptProto.fields.updateResponse = ProtoField.uint8( "dpt.service.updateResponse", "Update response", base.HEX, master.const.updateResponseByBytes )
dptProto.fields.updateSourceId = ProtoField.uint32( "dpt.service.updateSourceId", "Conversation ID (update source)" )

-- Topic details
dptProto.fields.topicDetails = ProtoField.string( "dpt.topic.details", "Topic details" )
dptProto.fields.topicDetailsLevel = ProtoField.string( "dpt.topic.details.level", "Detail level" )
dptProto.fields.topicDetailsSchema = ProtoField.string( "dpt.topic.details.schema", "Schema" )
dptProto.fields.topicDetailsAutoSubscribe = ProtoField.uint8( "dpt.topic.details.auto.subscribe", "Auto-subscribe", base.HEX, master.const.booleanByBtyes )
dptProto.fields.topicDetailsTidiesOnUnsubscribe = ProtoField.uint8( "dpt.topic.details.tidies.on.unsubscribe", "Tidies On Unsubscribe", base.HEX, master.const.booleanByBtyes )
dptProto.fields.topicDetailsTopicReference = ProtoField.string( "dpt.topic.details.topic.reference", "Topic reference" )
dptProto.fields.topicPropertiesNumber = ProtoField.uint32( "dpt.topic.properties.number", "Topic properties" )
dptProto.fields.topicDetailsEmptyValue = ProtoField.string( "dpt.topic.empty.field", "Empty field value" )
dptProto.fields.topicDetailsMasterTopic = ProtoField.string( "dpt.topic.master.topic", "Master topic" )
dptProto.fields.topicDetailsRoutingHandler = ProtoField.string( "dpt.topic.routing.handler", "Routing handler" )
dptProto.fields.topicDetailsCachesMetadata = ProtoField.uint8( "dpt.topic.caches.metadata", "Caches metadata", base.HEX, master.const.booleanByBtyes )
dptProto.fields.topicDetailsServiceType = ProtoField.string( "dpt.topic.service.type", "Service type" )
dptProto.fields.topicDetailsServiceHandler = ProtoField.string( "dpt.topic.service.handler", "Service handler" )
dptProto.fields.topicDetailsRequestTimeout = ProtoField.uint32( "dpt.topic.service.request.timeout", "Request timeout" )
dptProto.fields.topicDetailsCustomHandler = ProtoField.string( "dpt.topic.custom.handler", "Custom handler" )
dptProto.fields.topicDetailsProtoBufferClass = ProtoField.string( "dpt.topic.protobuffer.class", "Protocol Buffer class name" )
dptProto.fields.topicDetailsMessageName = ProtoField.string( "dpt.topic.message.name", "Message name" )
dptProto.fields.topicDetailsUpdateMode = ProtoField.uint8( "dpt.topic.update.mode", "Update mode", base.HEX, master.const.updateModeByByte )
dptProto.fields.topicDetailsDeletionValue = ProtoField.string( "dpt.topic.deletion.value", "Deletion value" )
dptProto.fields.topicDetailsOrdering = ProtoField.uint8( "dpt.topic.ordering", "Ordering", base.HEX, diffusion.const.ordering.byByte )
dptProto.fields.topicDetailsDuplicates = ProtoField.uint8( "dpt.topic.duplicates", "Duplicates", base.HEX, diffusion.const.duplicates.byByte )
dptProto.fields.topicDetailsOrder = ProtoField.uint8( "dpt.topic.order", "Order", base.HEX, diffusion.const.order.byByte )
dptProto.fields.topicDetailsRuleType = ProtoField.uint8( "dpt.topic.rule.type", "Rule type", base.HEX, diffusion.const.ruleType.byByte )
dptProto.fields.topicDetailsComparator = ProtoField.string( "dpt.topic.comparator", "Comparator" )
dptProto.fields.topicDetailsCollationRules = ProtoField.string( "dpt.topic.collation.rules", "Collation Rules" )
dptProto.fields.topicDetailsOrderKey = ProtoField.string( "dpt.topic.order.key", "Order key" )
dptProto.fields.topicDetailsOrderKeyFieldName = ProtoField.string( "dpt.topic.field.name", "Field name" )
dptProto.fields.topicProperty = ProtoField.string( "dpt.topic.property", "Topic Property" )
dptProto.fields.topicPropertyName = ProtoField.uint8( "dpt.topic.property.name", "Name", base.HEX, diffusion.const.topicProperty.byByte )
dptProto.fields.olderTopicPropertyName = ProtoField.uint8( "dpt.topic.property.name.older", "Name", base.HEX, diffusion.const.olderTopicProperty.byByte )
dptProto.fields.topicPropertyKey = ProtoField.string( "dpt.topic.property.key", "Key" )
dptProto.fields.topicPropertyValue = ProtoField.string( "dpt.topic.property.value", "Value" )

-- Add topic
dptProto.fields.addTopic = ProtoField.string( "dpt.service.addTopic", "Add topic" )
dptProto.fields.detailsReference = ProtoField.uint32( "dpt.service.topic.details.reference", "Topic details reference" )
dptProto.fields.initialValue = ProtoField.string( "dpt.service.topic.initial.value", "Initial value" )
dptProto.fields.topicAddResult = ProtoField.uint8( "dpt.service.topic.add.result", "Add result", base.HEX, master.const.addTopicResult )

-- Session listener registration
dptProto.fields.sessionListenerRegistration = ProtoField.string( "dpt.service.sessionListenerRegistration", "Session listener registration" )
dptProto.fields.detailTypeSet = ProtoField.string( "dpt.service.detailTypeSet", "Detail type set" )
dptProto.fields.detailType = ProtoField.uint8( "dpt.service.detailType", "Detail type", base.HEX, master.const.detailTypeByBytes )

-- Session listener notifications
dptProto.fields.sessionListenerEvent = ProtoField.string( "dpt.service.sessionListenerEvent", "Session listener event" )
dptProto.fields.sessionListenerEventType = ProtoField.uint8( "dpt.service.sessionListenerEventType", "Event type", base.HEX, master.const.sessionDetailsEventByBytes )
dptProto.fields.closeReason = ProtoField.uint8( "dpt.service.closeReason", "Close reason", base.HEX, master.const.closeReasonByBytes )
dptProto.fields.serviceSessionId = ProtoField.string( "dpt.service.sessionId", "Session Id")
dptProto.fields.sessionDetails = ProtoField.string( "dpt.service.sessionDetails", "Session Details" )
dptProto.fields.summary = ProtoField.string( "dpt.service.summary", "Summary" )
dptProto.fields.servicePrincipal = ProtoField.string( "dpt.service.principal", "Principal")
dptProto.fields.clientType = ProtoField.uint8( "dpt.service.clientType", "Client type", base.HEX, master.const.v5ClientTypeByBytes)
dptProto.fields.transportType = ProtoField.uint8( "dpt.service.transportType", "Transport type", base.HEX, master.const.transportTypeByBytes)
dptProto.fields.location = ProtoField.string( "dpt.service.location", "Location" )
dptProto.fields.address = ProtoField.string( "dpt.service.address", "Address" )
dptProto.fields.hostName = ProtoField.string( "dpt.service.hostName", "Hostname" )
dptProto.fields.resolvedName = ProtoField.string( "dpt.service.resolvedName", "Resolved name" )
dptProto.fields.addressType = ProtoField.uint8( "dpt.service.addressType", "Address type", base.HEX, master.const.addressTypeByBytes )
dptProto.fields.country = ProtoField.string( "dpt.service.country", "Country" )
dptProto.fields.language = ProtoField.string( "dpt.service.language", "Language" )
dptProto.fields.connectorName = ProtoField.string( "dpt.service.connectorName", "Connector name" )
dptProto.fields.serverName = ProtoField.string( "dpt.service.serverName", "Server name" )

-- Get session details request
dptProto.fields.lookupSessionDetails = ProtoField.string( "dpt.service.lookupSessionDetails", "Lookup" )

-- Conflate Client queue service
dptProto.fields.conflateClientQueue = ProtoField.string( "dpt.service.clientControl.conflateQueue", "Conflate Client Queue" )
dptProto.fields.conflateClientQueueEnabled = ProtoField.uint8( "dpt.service.clientControl.conflateQueue.enabled", "Conflate Client Queue", base.HEX, master.const.booleanByBtyes )

-- Client throttler service
dptProto.fields.throttleClientQueue = ProtoField.string( "dpt.service.clientControl.throttleQueue", "Throttle Client Queue" )
dptProto.fields.throttleClientQueueType = ProtoField.uint8( "dpt.service.clientControl.throttleQueue.type", "Throttler type", base.HEX, master.const.throttlerTypeByBytes )
dptProto.fields.throttleClientQueueLimit = ProtoField.uint32( "dpt.service.clientControl.throttleQueue.limit", "Throttler limit" )

-- Client close service
dptProto.fields.clientClose = ProtoField.string( "dpt.service.clientControl.clientClose", "Client close" )
dptProto.fields.clientCloseReason = ProtoField.string( "dpt.service.clientControl.clientClose.reason", "Client close reason" )

-- Topic notification services
dptProto.fields.topicNotificationType = ProtoField.uint8( "dpt.service.topicNotification.type", "Notification type", base.HEX, master.const.topicNotificationType )

-- Package footer
master.proto = {
	dptProto = dptProto
}
diffusion = master
return master.proto
