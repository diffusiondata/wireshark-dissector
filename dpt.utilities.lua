
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

-- Get the src host either from IPv4 or IPv6
local function srcHost()
	local ipv4SrcHost = field_ip_srchost()
	if ipv4SrcHost == nil then
		return field_ipv6_srchost().value
	else
		return ipv4SrcHost.value
	end
end

-- Get the dst host either from IPv4 or IPv6
local function dstHost()
	local ipv4DstHost = field_ip_dsthost()
	if ipv4DstHost == nil then
		return field_ipv6_dsthost().value
	else
		return ipv4DstHost.value
	end
end

-- Get the src port value
local function srcPort()
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

-- Package footer
master.utilities = {
	srcHost = srcHost,
	dstHost = dstHost,
	srcPort = srcPort,
	dump = dump,
	f_tcp_stream  = f_tcp_stream,
	f_time_epoch = f_time_epoch,
	RD = 1,
	FD = 2
}
diffusion = master
return master.utilities
