#!/usr/bin/env lua
-- Molch, an implementation of the axolotl ratchet based on libsodium
--
-- ISC License
--
-- Copyright (C) 2015-2016 1984not Security GmbH
-- Author: Max Bruckner (FSMaxB)
--
-- Permission to use, copy, modify, and/or distribute this software for any
-- purpose with or without fee is hereby granted, provided that the above
-- copyright notice and this permission notice appear in all copies.
--
-- THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
-- WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
-- MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
-- ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
-- WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
-- ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
-- OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package.path = "../?.lua;" .. package.path
package.cpath = "../?.so;../?.dylib;" .. package.cpath

local molch = require("molch")

-- users for alice and bob
local alice = molch.user.new()
local bob = molch.user.new()

-- stacks for sent packets
alice_sent = {}
bob_sent = {}

local alice_conversation = nil
local bob_conversation = nil

local backup = nil

local functions = {}

-- print what we're doing
local echo = false

function echo_on()
	if echo then
		print("> echo_on()")
	end

	echo = true
end
functions.echo_on = echo_on

function echo_off()
	if echo then
		print("> echo_off()")
	end
	echo = false
end
functions.echo_off = echo_off

function alice_send(message)
	if echo then
		print(string.format('> alice_send(%q)', message))
	end

	local packet
	if not alice_conversation then
		alice_conversation, packet = alice:start_send_conversation(message, bob.prekey_list, bob.id)
	else
		packet = alice_conversation:encrypt_message(message)
	end

	table.insert(alice_sent, {message = message, packet = packet})
end
functions.alice_send = alice_send

function bob_send(message)
	if echo then
		print(string.format('> bob_send(%q)', message))
	end

	local packet
	if not bob_conversation then
		bob_conversation, packet = bob:start_send_conversation(message, alice.prekey_list, alice.id)
	else
		packet = bob_conversation:encrypt_message(message)
	end

	table.insert(bob_sent, {message = message, packet = packet})
end
functions.bob_send = bob_send

function alice_receive(number)
	if echo then
		if number then
			print(string.format('> alice_receive(%i)', number))
		else
			print('> alice_receive()')
		end
	end

	number = number or 1

	local message
	local receive_message_number
	local previous_receive_message_number
	local packet = table.remove(bob_sent, number).packet

	if not alice_conversation then
		alice_conversation, message = alice:start_receive_conversation(packet, bob.id)
		receive_message_number = 0
		previous_receive_message_number = 0
	else
		message, receive_message_number, previous_receive_message_number = alice_conversation:decrypt_message(packet)
	end

	print(receive_message_number, previous_receive_message_number)
	print(message)

	return message, receive_message_number, previous_receive_message_number
end
functions.alice_receive = alice_receive

function bob_receive(number)
	if echo then
		if number then
			print(string.format('> bob_receive(%i)', number))
		else
			print('> bob_receive()')
		end
	end

	number = number or 1

	local message
	local receive_message_number
	local previous_receive_message_number
	local packet = table.remove(alice_sent, number).packet

	if not bob_conversation then
		bob_conversation, message = bob:start_receive_conversation(packet, alice.id)
		receive_message_number = 0
		previous_receive_message_number = 0
	else
		message, receive_message_number, previous_receive_message_number = bob_conversation:decrypt_message(packet)
	end

	print(receive_message_number, previous_receive_message_number)
	print(message)

	return message, receive_message_number, previous_receive_message_number
end
functions.bob_receive = bob_receive

function alice_packets()
	if echo then
		print("> alice_packets()")
	end

	for i,entry in ipairs(alice_sent) do
		print(i .. ": Length " .. #entry.packet)
		molch.print_hex(entry.packet)
		print("\n")
	end
end
functions.alice_packets = alice_packets

function alice_messages()
	if echo then
		print("> alice_messages()")
	end

	for i,entry in ipairs(alice_sent) do
		print(i .. ": Length " .. #entry.message)
		print(entry.message)
		print("")
	end
end
functions.alice_messages = alice_messages

function bob_packets()
	if echo then
		print("> bob_packets()")
	end

	for i,entry in ipairs(bob_sent) do
		print(i .. ": Length " .. #entry.packet)
		molch.print_hex(entry.packet)
		print("\n")
	end
end
functions.bob_packets = bob_packets

function bob_messages()
	if echo then
		print("> bob_messages()")
	end

	for i,entry in ipairs(bob_sent) do
		print(i .. ": Length " .. #entry.message)
		print(entry.message)
		print("")
	end
end
functions.bob_messages = bob_messages

function export()
	if echo then
		print("> export()")
	end

	backup = molch.export()
end
functions.export = export

function import()
	if echo then
		print("> import()")
	end

	molch.import(backup)
end
functions.import = import

function restart()
	if echo then
		print("> restart()")
	end

	local alice_id = alice.id
	local bob_id = bob.id

	backup = molch.export()
	molch.destroy_all_users()
	molch.import(backup)

	alice = molch.users[alice_id]
	alice_conversation = alice.conversations[alice.conversations[1]]
	bob = molch.users[bob_id]
	bob_conversation = bob.conversations[bob.conversations[1]]
end
functions.restart = restart

function errors_on()
	if echo then
		print("> errors_on()")
	end

	for name,func in pairs(functions) do
		_G[name] = function (...)
			local return_values = {xpcall(func, function (error_message)
				print(error_message)
				print(debug.traceback())
			end,
			...)}

			local status = table.remove(return_values, 1)
			if not status then
				os.exit(status)
			end

			return table.unpack(return_values)
		end
	end
end

function errors_off()
	if echo then
		print("> errors_off()")
	end

	for name, func in pairs(functions) do
		_G[name] = func
	end
end

dofile(arg[1])
