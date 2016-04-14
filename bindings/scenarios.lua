local molch = require("molch")

-- users for alice and bob
local alice = molch.user.new()
local bob = molch.user.new()

-- stacks for sent packets
local alice_sent = {}
local bob_sent = {}

local alice_conversation = nil
local bob_conversation = nil

-- print what we're doing
local echo = false

function echo_on()
	if echo then
		print("> echo_on()")
	end

	echo = true
end

function echo_off()
	if echo then
		print("> echo_off()")
	end
	echo = false
end

function alice_send(message)
	if echo then
		print(string.format('> alice_send(%q)', message))
	end

	local packet
	if not alice_conversation then
		alice_conversation, packet = alice:create_send_conversation(message, bob.prekey_list, bob.id)
	else
		packet = alice_conversation:encrypt_message(message)
	end

	table.insert(alice_sent, {message = message, packet = packet})
end

function bob_send(message)
	if echo then
		print(string.format('> bob_send(%q)', message))
	end

	local packet
	if not bob_conversation then
		bob_conversation, packet = bob:create_send_conversation(message, alice.prekey_list, alice.id)
	else
		packet = bob_conversation:encrypt_message(message)
	end

	table.insert(bob_sent, {message = message, packet = packet})
end

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
	local packet = table.remove(bob_sent, number).packet

	if not alice_conversation then
		alice_conversation, message = alice:create_receive_conversation(packet, bob.id)
	else
		message = alice_conversation:decrypt_message(packet)
	end

	print(message)
end

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
	local packet = table.remove(alice_sent, number).packet

	if not bob_conversation then
		bob_conversation, message = bob:create_receive_conversation(packet, alice.id)
	else
		message = bob_conversation:decrypt_message(packet)
	end

	print(message)
end

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
