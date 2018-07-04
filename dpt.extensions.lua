
local master = diffusion or {}
if master.extensions ~= nil then
	return master.extensions
end
local RD, FD = master.utilities.RD, master.utilities.FD

-- Mark up non-printing delimiters
function string:escapeDiff()
	local result = self:gsub( string.char(RD), "<RD>" )
	return (result:gsub( string.char(FD), "<FD>" ))
end

function string:toRecordString()
	return string.format( "[%s]", self:gsub( string.char(FD), ", " ) )
end

function string:startsWith( prefix )
	local prefixLength = string.len( prefix )
	local actualPrefix = string.sub( self, 1, prefixLength )
	return actualPrefix == prefix
end

-- Split a string into fields by the given delimited
function string:split(sep)
    local sep, fields = sep or ":", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

-- Package footer
master.extensions = {}
diffusion = master
return master.extensions
