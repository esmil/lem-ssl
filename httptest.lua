#!/usr/bin/env lem

local utils   = require 'lem.utils'
local ssl     = require 'lem.ssl'
local http    = require 'lem.http'

local context = assert(ssl.newcontext())

local format = string.format
local concat = table.concat

local ticker = utils.sleeper()

utils.spawn(function()
	local istream, ostream = assert(context:connect('encrypted.google.com:https'))

	print('\nConnected.')

	for i = 1, 2 do
		--assert(ostream:write('GET / HTTP/1.1\r\nHost: www.google.dk\r\nConnection: close\r\n\r\n'))
		assert(ostream:write('GET / HTTP/1.1\r\nHost: encrypted.google.com\r\n\r\n'))

		local res = assert(istream:read('HTTPResponse'))

		print(format('\nHTTP/%s %d %s', res.version, res.status, res.text))
		for k, v in pairs(res.headers) do
			print(format('%s: %s', k, v))
		end

		print(format('\n#body = %d', #assert(res:body())))
	end

	ticker:wakeup(true)
end)

local write = io.write
repeat
	write('.')
until ticker:sleep(0.001)

-- vim: set ts=2 sw=2 noet:
