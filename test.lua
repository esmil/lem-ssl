#!/usr/bin/env lem
--
-- This file is part of lem-ssl.
-- Copyright 2011-2012 Emil Renner Berthing
--
-- lem-ssl is free software: you can redistribute it and/or
-- modify it under the terms of the GNU General Public License as
-- published by the Free Software Foundation, either version 3 of
-- the License, or (at your option) any later version.
--
-- lem-ssl is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with lem-ssl.  If not, see <http://www.gnu.org/licenses/>.
--

local ssl = require 'lem.ssl'

local context = assert(ssl.newcontext())
local iconn, oconn = assert(context:connect('encrypted.google.com:https'))

assert(getmetatable(iconn) == ssl.IStream, 'IStream metatable confusion')
assert(getmetatable(oconn) == ssl.OStream, 'OStream metatable confusion')

assert(oconn:write('GET / HTTP/1.1\r\nHost: encrypted.google.com\r\nConnection: close\r\n\r\n'))

--[[
while true do
	local line, err = iconn:read('*l')
	if not line then
		if err == 'closed' then
			break
		else
			error(err)
		end
	end

	print(line)
end
--[=[
--]]
print(assert(iconn:read('*a')))
--]=]

-- vim: ts=2 sw=2 noet:
