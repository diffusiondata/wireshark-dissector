
-- Utilities package
-- This package provides common utilities and constants.

-- Package header
local master = diffusion or {}
if master.utilities ~= nil then
	return master.utilities
end


local field_ip_dsthost  = Field.new("ip.dst_host")
local field_ip_srchost  = Field.new("ip.src_host")
local field_ipv6_dsthost  = Field.new("ipv6.dst_host")
local field_ipv6_srchost  = Field.new("ipv6.src_host")
local field_tcp_srcport = Field.new("tcp.srcport")
local field_tcp_stream  = Field.new("tcp.stream")
local field_time_epoch = Field.new("frame.time_epoch")
local field_frame_number = Field.new("frame.number")
local field_http_response_code = Field.new("http.response.code")
local field_http_connection = Field.new("http.connection")
local field_http_upgrade = Field.new("http.upgrade")
local field_http_uri = Field.new("http.request.uri")
local field_http_request_line = Field.new("http.request.line")
local field_ws_payload_length = Field.new("websocket.payload_length")
local field_ws_payload_length_ext_16 = Field.new("websocket.payload_length_ext_16")
local field_ws_binary_payload
local field_ws_text_payload

-- Attempt to set the websocket fields to those used by Wireshark 1.12
local function set_version_112_fields()
	field_ws_binary_payload = Field.new("websocket.payload.binary")
	field_ws_text_payload = Field.new("websocket.payload.text")
end

-- Attempt to set the websocket fields to those used by Wireshark 1.99
local function set_version_199_fields()
	field_ws_binary_payload = Field.new("data.data")
	field_ws_text_payload = Field.new("data-text-lines")
end

if not pcall(set_version_112_fields) then
	set_version_199_fields()
end

-- Get the src host either from IPv4 or IPv6
local function f_src_host()
	local ipv4SrcHost = field_ip_srchost()
	if ipv4SrcHost == nil then
		return field_ipv6_srchost().value
	else
		return ipv4SrcHost.value
	end
end

-- Get the dst host either from IPv4 or IPv6
local function f_dst_host()
	local ipv4DstHost = field_ip_dsthost()
	if ipv4DstHost == nil then
		return field_ipv6_dsthost().value
	else
		return ipv4DstHost.value
	end
end

-- Get the src port value
local function f_src_port()
	return field_tcp_srcport().value
end

-- Get the tcp stream value
local function f_tcp_stream()
	return field_tcp_stream().value
end

-- Get the frame time stamp value
local function f_time_epoch()
	return field_time_epoch().value
end

-- Get the frame number
local function f_frame_number()
	return field_frame_number().value
end

local function dump(o)
	if type(o) == 'table' then
	local s = '{ '
	for k,v in pairs(o) do
	if type(k) ~= 'number' then k = '"'..k..'"' end
		s = s .. '['..k..'] = ' .. dump(v) .. ','
	end
		return s .. '} '
	else
		return tostring(o)
	end
end

local function f_http_response_code()
	local f = field_http_response_code()
	if f ~= nil then
		return f.value
	else
		return nil
	end
end

local function f_http_connection()
	local f = field_http_connection()
	if f ~= nil then
		return f.value
	else
		return nil
	end
end

local function f_http_upgrade()
	local f = field_http_upgrade()
	if f ~= nil then
		return f.value
	else
		return nil
	end
end

local function f_http_uri()
	local f = field_http_uri()
	if f ~= nil then
		return f.range
	else
		return nil
	end
end

-- Return a numbered table containing the ranges of each HTTP header
local function f_http_request_lines()
	local f = {field_http_request_line()}
	if f ~= nil then
		local headers = {}
		for i in pairs(f) do
			headers[i] = f[i].range
		end
		return headers
	else
		return nil
	end
end

-- Return a table containing the ranges of each HTTP header mapping from the
-- header field name
local function f_http_request_headers()
	local lines = f_http_request_lines()

	if lines ~= nil then
		local headers = {}
		for i in pairs(lines) do
			local fieldEnd = 0;

			-- Find end of field name
			while fieldEnd < lines[i]:len() do
				local character = lines[i]( fieldEnd, 1 ):string();
				if character ~= ":" and character ~= " " then
					fieldEnd = fieldEnd + 1
				else
					break
				end
			end

			-- Find start of value
			local valueStart = fieldEnd;
			while valueStart < lines[i]:len() do
				local character = lines[i]( valueStart, 1 ):string();
				if character == ":" or character == " " or character == "\n" or character == "\r" then
					valueStart = valueStart + 1
				else
					break
				end
			end

			-- Find end of value
			local valueEnd = valueStart;
			while valueEnd < lines[i]:len() do
				local character = lines[i]( valueEnd, 1 ):string();
				if character ~= "\n" and character ~= "\r" then
					valueEnd = valueEnd + 1
				else
					break
				end
			end

			local field = lines[i]( 0, fieldEnd ):string()

			headers[field] = lines[i]( valueStart, valueEnd - valueStart )
		end
		return headers
	else
		return nil
	end
end

local function f_ws_b_payload()
	local f = {field_ws_binary_payload()}
	if f ~= nil then
		local payloads = {}
		for i in pairs(f) do
			payloads[i] = f[i].range
		end
		return payloads
	else
		return nil
	end
end

local function f_ws_t_payload()
	local f = {field_ws_text_payload()}
	if f ~= nil then
		local payloads = {}
		for i in pairs(f) do
			payloads[i] = f[i].range
		end
		return payloads
	else
		return nil
	end
end

local function ws_payload_length()
	local len = field_ws_payload_length_ext_16() or field_ws_payload_length()
	if len ~= nil then
		return len.value
	else
		return nil
	end
end

--- Returns representation of num in radix
local function int_to_string(num, radix)
    local charrange = '0123456789abcdefghijklmnopqrstuvwxyz'
    local s = ''
    while num > 0 do
        local mod = math.fmod(num, radix)
        s = string.sub(charrange, mod+1, mod+1) .. s
        num = math.floor(num / radix)
    end
    if s == '' then s = '0' end
    return s
end

-- Find the delimeterCount-th occurance of ch in this, or -1. delimeterCount indexes from zero.
local function indexn(ba, ch, delimiterCount)
	for i = 0, ba:len()-1 do
		if ba:get_index( i ) == ch then
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
local function index(ba, ch)
	for i = 0, ba:len()-1 do
		if ba:get_index( i ) == ch then return i end
	end
	return -1
end

-- Package footer
master.utilities = {
	f_src_host = f_src_host,
	f_dst_host = f_dst_host,
	f_src_port = f_src_port,
	dump = dump,
	f_tcp_stream  = f_tcp_stream,
	f_time_epoch = f_time_epoch,
	f_frame_number = f_frame_number,
	f_http_response_code = f_http_response_code,
	f_http_connection = f_http_connection,
	f_http_upgrade = f_http_upgrade,
	f_http_uri = f_http_uri,
	f_http_request_headers = f_http_request_headers,
	f_ws_b_payload = f_ws_b_payload,
	f_ws_t_payload = f_ws_t_payload,
	ws_payload_length = ws_payload_length,
	int_to_string = int_to_string,
	RD = 0x01,
	FD = 0x02,
	WSMD = 0x08,
	indexn = indexn,
	index = index
}
diffusion = master
return master.utilities
