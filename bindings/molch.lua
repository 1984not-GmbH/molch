local molch = {}

local molch_interface = require("molch-interface")

function molch.read_file(filename)
	local file = io.open(filename, "rb")
	local content = file:read("*all")
	file:close()
	return content
end

function recursively_delete_table(t)
	for key, value in pairs(t) do
		if type(value) == 'table' then
			recursively_delete_table(value)
		end
		t[key] = nil
	end
end

function convert_to_lua_string(data, size)
	size = (type(size) == 'userdata') and size:value() or size
	local characters = {}
	for i = 0, size - 1 do
		table.insert(characters, string.char(data[i]))
	end
	return table.concat(characters)
end

function convert_to_c_string(data)
	local new_string = molch_interface.ucstring_array(#data)

	for i = 0, #data - 1 do
		new_string[i] = string.byte(data, i + 1)
	end

	return new_string, #data
end

function copy_callee_allocated_string(pointer, length, free)
	length = (type(length) == 'userdata') and length:value() or length
	free = free or molch_interface.free

	local free_pointer = true
	if swig_type(pointer) == "unsigned char **" then
		pointer = molch_interface.dereference_ucstring_pointer(pointer)
		free_pointer = false
	end

	local new_string = molch_interface.ucstring_array(length)
	molch_interface.ucstring_copy(new_string, pointer, length)
	free(pointer)
	if free_pointer then
		molch_interface.free(pointer_pointer)
	end

	return new_string
end

function molch.print_hex(data, width)
	width = width or 16
	for i = 1, #data do
		if ((i - 1) % width) == 0 then
			io.write("\n")
		end
		io.write(string.format("%.2X ", string.byte(data, i)))
	end
	io.write('\n')
end

-- table containing references to all users
local users = {
	attributes = {
		json = ""
	}
}

molch.user = {}
molch.user.__index = molch.user

molch.conversation = {}
molch.conversation.__index = molch.conversation


function molch.user.new(random_spice --[[optional]])
	local user = {}
	setmetatable(user, molch.user)

	local raw_id = molch_interface.ucstring_array(32)
	local prekey_list_length = molch_interface.size_t()
	local json_length = molch_interface.size_t()


	local spice_userdata, spice_userdata_length = random_spice and convert_to_c_string(random_spice) or nil, 0

	-- this will be allocated by molch!
	local temp_prekey_list = molch_interface.create_ucstring_pointer()
	local temp_json = molch_interface.create_ucstring_pointer()

	local status = molch_interface.molch_create_user(
		raw_id,
		temp_prekey_list,
		prekey_list_length,
		spice_userdata,
		spice_userdata_length,
		temp_json,
		json_length
	)
	if status ~= 0 then
		molch_interface.free(temp_prekey_list)
		molch_interface.free(temp_json)
		error("Failed to create user!")
	end

	-- copy the prekey list over to an array managed by swig and free the old
	local raw_prekey_list = copy_callee_allocated_string(temp_prekey_list, prekey_list_length)
	-- copy the json over to an array managed by swig and free the old
	local raw_json = copy_callee_allocated_string(temp_json, json_length, molch_interface.sodium_free)

	-- create lua strings from the data
	user.id = convert_to_lua_string(raw_id, 32)
	user.prekey_list = convert_to_lua_string(raw_prekey_list, prekey_list_length)
	user.json = convert_to_lua_string(raw_json, json_length)
	users.attributes.json = user.json

	-- add to global list of users
	users[user.id] = user

	user.conversations = {}

	return user
end

function molch.user:destroy()
	molch_interface.molch_destroy_user(
		convert_to_c_string(self.id),
		nil,
		nil)

	-- remove from list of users
	users[self.id] = nil

	setmetatable(self, nil)
	recursively_delete_table(self)
end

function molch.user_count()
	return molch_interface.molch_user_count()
end
molch.user.count = molch.user_count

function molch.user_list()
	local count = molch_interface.size_t()
	local raw_list = molch_interface.molch_user_list(count)
	local raw_list = copy_callee_allocated_string(raw_list, count:value() * 32)
	local lua_raw_list = convert_to_lua_string(raw_list, count:value() * 32)

	local list = {}
	for i = 0, count:value() - 1 do
		local id = lua_raw_list:sub(i * 32 + 1, i * 32 + 32)
		table.insert(list, id)
	end

	return list
end
molch.user.list = molch.user_list

function molch.json_export()
	local json_length = molch_interface.size_t()

	local json
	if molch.user_count() == 0 then -- work around ugly bug that makes it crash under some circumstances when using sodium_malloc
		users.attributes.json = "[]\0"
		json = convert_to_c_string(users.attributes.json)
	else
		local temp_json = molch_interface.molch_json_export(json_length)
		if not temp_json then
			error("Failed to export JSON.")
		end

		json = copy_callee_allocated_string(temp_json, json_length, molch_interface.sodium_free)
		users.attributes.json = convert_to_lua_string(json, json_length)
	end


	if self then -- called on an object
		self.json = users.attributes.json
	end

	return users.attributes.json
end
molch.user.json_export = molch.json_export

function molch.destroy_all_users()
	for user_id,user in pairs(users) do
		if user_id ~= "attributes" then
			user:destroy()
		end
	end

	molch_interface.molch_destroy_all_users()

	recursively_delete_table(users)

	users.attributes = {
		json = ""
	}
end

function molch.get_message_type(packet)
	local packet_string, length = convert_to_c_string(packet)
	local message_type = molch_interface.molch_get_message_type(packet_string, length)
	if message_type == molch_interface.PREKEY_MESSAGE then
		return "PREKEY_MESSAGE"
	elseif message_type == molch_interface.NORMAL_MESSAGE then
		return "NORMAL_MESSAGE"
	elseif message_type == molch_interface.INVALID then
		return "INVALID"
	else
		error("No valid message type")
	end
end

function molch.user:list_conversations()
	local count = molch_interface.size_t()
	local raw_list = molch_interface.molch_list_conversations(convert_to_c_string(self.id), count)
	raw_list = copy_callee_allocated_string(raw_list, count:value() * molch_interface.CONVERSATION_ID_SIZE)
	local lua_raw_list = convert_to_lua_string(raw_list, count:value() * molch_interface.CONVERSATION_ID_SIZE)

	local list = {}
	for i = 0, count:value() - 1 do
		local conversation_id = lua_raw_list:sub(i * molch_interface.CONVERSATION_ID_SIZE + 1, (i + 1) * molch_interface.CONVERSATION_ID_SIZE)
		table.insert(list, conversation_id)
	end

	return list
end

function molch.json_import(json)
	local json_string, json_length = convert_to_c_string(json)

	local status = molch_interface.molch_json_import(json_string, json_length)
	if status ~= 0 then
		error("Failed to import JSON.")
	end

	-- update global user list
	local user_list = molch.user_list()
	local user_id_lookup = {}
	for _,user_id in ipairs(user_list) do
		user_id_lookup[user_id] = true

		if users[user_id] then
			recursively_delete_table(users[user_id])
		else
			users[user_id] = {}
			setmetatable(users[user_id], molch.user)
		end

		local user = users[user_id]
		user.id = user_id
		user.json = json
		users.attributes.json = json

		-- add the conversations
		user.conversations = user:list_conversations()
		for _,conversation_id in ipairs(user:list_conversations()) do
			user.conversations[conversation_id] = {id = conversation_id}
			setmetatable(user.conversations[conversation_id], molch.conversation)
		end
	end

	-- remove users that don't exist anymore
	for user_id,user in pairs(users) do
		if not user_id_lookup[user_id] then
			recursively_delete_table(user)
			users[user_id] = nil
		end
	end
end

function molch.user:create_send_conversation(message, prekey_list, receiver_id)
	local conversation = {}
	setmetatable(conversation, molch.conversation)

	local raw_conversation_id = molch_interface.ucstring_array(molch_interface.CONVERSATION_ID_SIZE)
	local raw_packet = molch_interface.create_ucstring_pointer()
	local raw_packet_length = molch_interface.size_t()
	local raw_json = molch_interface.create_ucstring_pointer()
	local raw_json_length = molch_interface.size_t()

	local raw_message, raw_message_length = convert_to_c_string(message)
	local raw_prekey_list, raw_prekey_list_length = convert_to_c_string(prekey_list)

	local status = molch_interface.molch_create_send_conversation(
		raw_conversation_id,
		raw_packet,
		raw_packet_length,
		raw_message,
		raw_message_length,
		raw_prekey_list,
		raw_prekey_list_length,
		convert_to_c_string(self.id),
		convert_to_c_string(receiver_id),
		raw_json,
		raw_json_length)
	if status ~= 0 then
		molch_interface.free(raw_packet)
		molch_interface.free(raw_json)
		error("Failed to create send conversation.")
	end

	local conversation_id = convert_to_lua_string(raw_conversation_id, molch_interface.CONVERSATION_ID_SIZE)
	raw_packet = copy_callee_allocated_string(raw_packet, raw_packet_length)
	raw_json = copy_callee_allocated_string(raw_json, raw_json_length, molch_interface.sodium_free)

	local packet = convert_to_lua_string(raw_packet, raw_packet_length)
	local json = convert_to_lua_string(raw_json, raw_json_length)

	conversation.json = json
	conversation.id = conversation_id

	-- add to the users list of conversations
	self.conversations[conversation_id] = conversation

	return conversation, packet
end

function molch.user:create_receive_conversation(packet, sender_id)
	local conversation = {}
	setmetatable(conversation, molch.conversation)

	local raw_conversation_id = molch_interface.ucstring_array(molch_interface.CONVERSATION_ID_SIZE)
	local raw_message = molch_interface.create_ucstring_pointer()
	local raw_message_length = molch_interface.size_t()
	local raw_prekey_list = molch_interface.create_ucstring_pointer()
	local raw_prekey_list_length = molch_interface.size_t()
	local raw_json = molch_interface.create_ucstring_pointer()
	local raw_json_length = molch_interface.size_t()

	local raw_packet, raw_packet_length = convert_to_c_string(packet)

	local status = molch_interface.molch_create_receive_conversation(
		raw_conversation_id,
		raw_message,
		raw_message_length,
		raw_packet,
		raw_packet_length,
		raw_prekey_list,
		raw_prekey_list_length,
		convert_to_c_string(sender_id),
		convert_to_c_string(self.id),
		raw_json,
		raw_json_length)
	if status ~= 0 then
		molch_interface.free(raw_message)
		molch_interface.free(raw_prekey_list)
		molch_interface.free(raw_json)
		error("Failed to create send conversation.")
	end

	local conversation_id = convert_to_lua_string(raw_conversation_id, molch_interface.CONVERSATION_ID_SIZE)
	raw_message = copy_callee_allocated_string(raw_message, raw_message_length)
	raw_prekey_list = copy_callee_allocated_string(raw_prekey_list, raw_prekey_list_length)
	raw_json = copy_callee_allocated_string(raw_json, raw_json_length, molch_interface.sodium_free)

	local message = convert_to_lua_string(raw_message, raw_message_length)
	local prekey_list = convert_to_lua_string(raw_prekey_list, raw_prekey_list_length)
	local json = convert_to_lua_string(raw_json, raw_json_length)

	conversation.json = json
	conversation. id = conversation_id
	self.prekey_list = prekey_list

	-- add to the users list of conversations
	self.conversations[conversation_id] = conversation

	return conversation, message
end

function molch.conversation:encrypt_message(message)
	local raw_message, raw_message_length = convert_to_c_string(message)
	local raw_packet = molch_interface.create_ucstring_pointer()
	local raw_packet_length = molch_interface.size_t()
	local raw_json = molch_interface.create_ucstring_pointer()
	local raw_json_length = molch_interface.size_t()

	local status = molch_interface.molch_encrypt_message(
		raw_packet,
		raw_packet_length,
		raw_message,
		raw_message_length,
		convert_to_c_string(self.id),
		raw_json,
		raw_json_length)
	if status ~= 0 then
		molch_interface.free(raw_packet)
		molch_interface.free(raw_json)
		error("Failed to encrypt message!")
	end

	raw_packet = copy_callee_allocated_string(raw_packet, raw_packet_length)
	raw_json = copy_callee_allocated_string(raw_json, raw_json_length, molch_interface.sodium_free)

	local packet = convert_to_lua_string(raw_packet, raw_packet_length)
	self.json = convert_to_lua_string(raw_json, raw_json_length)

	return packet
end

function molch.conversation:decrypt_message(packet)
	local raw_packet, raw_packet_length = convert_to_c_string(packet)
	local raw_message = molch_interface.create_ucstring_pointer()
	local raw_message_length = molch_interface.size_t()
	local raw_json = molch_interface.create_ucstring_pointer()
	local raw_json_length = molch_interface.size_t()

	local status = molch_interface.molch_decrypt_message(
		raw_message,
		raw_message_length,
		raw_packet,
		raw_packet_length,
		convert_to_c_string(self.id),
		raw_json,
		raw_json_length)
	if status ~= 0 then
		molch_interface.free(raw_message)
		molch_interface.free(raw_json)
		error("Failed to decrypt message.")
	end

	raw_message = copy_callee_allocated_string(raw_message, raw_message_length)
	raw_json = copy_callee_allocated_string(raw_json, raw_json_length, molch_interface.sodium_free)

	local message = convert_to_lua_string(raw_message, raw_message_length)
	self.json = convert_to_lua_string(raw_json, raw_json_length)

	return message
end

function molch.conversation:destroy()
	-- search the user that the conversation belongs to
	local containing_user
	for id,user in pairs(users) do
		if (id ~= 'attributes') and user.conversations[self.id] then
			containing_user = user
			break
		end
	end

	local raw_json = molch_interface.create_ucstring_pointer()
	local raw_json_length = molch_interface.size_t()

	molch_interface.molch_end_conversation(
		convert_to_c_string(self.id),
		raw_json,
		raw_json_length)

	raw_json = copy_callee_allocated_string(raw_json, raw_json_length --[[FIXME Why does this crash?, molch_interface.sodium_free]])

	local json = convert_to_lua_string(raw_json, raw_json_length)

	containing_user.json = json
	users.attributes.json = json

	containing_user.conversations[self.id] = nil
	recursively_delete_table(self)
end

return molch
