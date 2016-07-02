local molch = {}

print("WARNING: This interface should only be used for debugging!")

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
		backup = {},
		last_backup_key = ""
	}
}
molch.users = users

molch.user = {}
molch.user.__index = molch.user

molch.conversation = {}
molch.conversation.__index = molch.conversation

molch.backup = {}
molch.backup.__index = molch.backup

function molch.backup.new(content, length, key)
	local backup = {
		content = "",
		key = ""
	}

	setmetatable(backup, molch.backup)

	if content and (key or users.attributes.last_backup_key) then
		backup:set(content, length, key)
	end


	return backup
end

function molch.backup:set(content, length, key)
	key = key or molch.users.attributes.last_backup_key

	if type(content) == "string" then
		self.content = content
	else
		self.content = convert_to_lua_string(content, length)
	end

	if type(key) == "string" then
		self.key = key
	else
		self.key = convert_to_lua_string(key, 32)
	end
end

function molch.backup:to_c()
	local raw_content, content_length = convert_to_c_string(self.content)
	local raw_key, key_length = convert_to_c_string(self.key)

	return raw_content, content_length, raw_key, key_length
end

function molch.backup:copy()
	local copy = molch.backup.new()
	copy:set(self.content, nil, self.key)

	return copy
end

function molch.user.new(random_spice --[[optional]])
	local user = {}
	setmetatable(user, molch.user)

	local raw_id = molch_interface.ucstring_array(32)
	local raw_backup_key = molch_interface.ucstring_array(32)
	local prekey_list_length = molch_interface.size_t()
	local backup_length = molch_interface.size_t()


	local spice_userdata, spice_userdata_length = random_spice and convert_to_c_string(random_spice) or nil, 0

	-- this will be allocated by molch!
	local temp_prekey_list = molch_interface.create_ucstring_pointer()
	local temp_backup = molch_interface.create_ucstring_pointer()

	local status = molch_interface.molch_create_user(
		raw_id,
		32,
		temp_prekey_list,
		prekey_list_length,
		spice_userdata,
		spice_userdata_length,
		raw_backup_key,
		32,
		temp_backup,
		backup_length
	)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.molch_destroy_return_status(status)
		molch_interface.free(temp_prekey_list)
		molch_interface.free(temp_backup)
		error(molch.print_errors(status))
	end

	-- copy the prekey list over to an array managed by swig and free the old
	local raw_prekey_list = copy_callee_allocated_string(temp_prekey_list, prekey_list_length)
	-- copy the backup over to an array managed by swig and free the old
	local raw_backup = copy_callee_allocated_string(temp_backup, backup_length)

	-- create lua strings from the data
	user.id = convert_to_lua_string(raw_id, 32)
	user.prekey_list = convert_to_lua_string(raw_prekey_list, prekey_list_length)

	-- create backup object
	user.backup = molch.backup.new(raw_backup, backup_length, raw_backup_key)
	users.attributes.backup = user.backup:copy()

	users.attributes.last_backup_key = user.backup.key

	-- add to global list of users
	users[user.id] = user

	user.conversations = {}

	return user
end

function molch.user:destroy()
	local status = molch_interface.molch_destroy_user(
		convert_to_c_string(self.id),
		#self.id,
		nil,
		nil)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		error(molch.print_errors())
	end

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
	local list_length = molch_interface.size_t()
	local raw_list = molch_interface.create_ucstring_pointer()
	local status = molch_interface.molch_user_list(raw_list, list_length, count)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		error(molch.print_errors(status))
	end
	local raw_list = copy_callee_allocated_string(raw_list, list_length)
	local lua_raw_list = convert_to_lua_string(raw_list, list_length)

	local list = {}
	for i = 0, count:value() - 1 do
		local id = lua_raw_list:sub(i * 32 + 1, i * 32 + 32)
		table.insert(list, id)
	end

	return list
end
molch.user.list = molch.user_list

function molch:export()
	local backup_length = molch_interface.size_t()

	local backup
	local raw_backup = molch_interface.create_ucstring_pointer()
	local status = molch_interface.molch_export(raw_backup, backup_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		error(molch.print_errors(status))
	end

	raw_backup = copy_callee_allocated_string(raw_backup, backup_length)
	users.attributes.backup = molch.backup.new(raw_backup, backup_length)

	if self then -- called on an object
		self.backup = users.attributes.backup:copy()
	end

	return users.attributes.backup:copy()
end
molch.user.backup_export = molch.backup_export

function molch.destroy_all_users()
	for user_id,user in pairs(users) do
		if user_id ~= "attributes" then
			user:destroy()
		end
	end

	molch_interface.molch_destroy_all_users()

	recursively_delete_table(users)

	users.attributes = {
		backup = ""
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
	local raw_list = molch_interface.create_ucstring_pointer()
	local status = molch_interface.molch_list_conversations(convert_to_c_string(self.id), raw_list, count)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		error(molch.print_errors(status))
	end
	if count:value() == 0 then
		return {}
	end
	raw_list = copy_callee_allocated_string(raw_list, count:value() * molch_interface.CONVERSATION_ID_SIZE)
	local lua_raw_list = convert_to_lua_string(raw_list, count:value() * molch_interface.CONVERSATION_ID_SIZE)

	local list = {}
	for i = 0, count:value() - 1 do
		local conversation_id = lua_raw_list:sub(i * molch_interface.CONVERSATION_ID_SIZE + 1, (i + 1) * molch_interface.CONVERSATION_ID_SIZE)
		table.insert(list, conversation_id)
	end

	return list
end

function molch.import(backup)
	local backup_string, backup_length, raw_backup_key = backup:to_c()
	local new_backup_key = molch_interface.ucstring_array(32)

	local status = molch_interface.molch_import(
		backup_string,
		backup_length,
		raw_backup_key,
		new_backup_key)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		error(molch.print_errors(status))
	end

	users.attributes.backup = backup
	users.attributes.last_backup_key = convert_to_lua_string(new_backup_key, 32)

	-- backup of all running conversations
	local conversation_backup = {}
	for user_id, user in pairs(users) do
		if user_id ~= "attributes" then
			for conversation_id, conversation in pairs(user.conversations) do
				if type(conversation) ~= "string" then
					conversation_backup[conversation_id] = conversation
					user.conversations[conversation_id] = nil
				end
			end
		end
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
		user.backup = backup

		-- add the conversations
		user.conversations = user:list_conversations()
		for _,conversation_id in ipairs(user:list_conversations()) do
			if conversation_backup[conversation_id] then
				user.conversations[conversation_id] = conversation_backup[conversation_id]
				conversation_backup[conversation_id] = nil
			else
				user.conversations[conversation_id] = {id = conversation_id}
				setmetatable(user.conversations[conversation_id], molch.conversation)
			end
		end
	end

	-- remove users that don't exist anymore
	for user_id,user in pairs(users) do
		if (not user_id == "attributes") and (not user_id_lookup[user_id]) then
			recursively_delete_table(user)
			users[user_id] = nil
		end
	end

	-- destroy conversations that don't exist anymore
	for _, conversation in pairs(conversation_backup) do
		recursively_delete_table(conversation)
	end
end

function molch.user:create_send_conversation(message, prekey_list, receiver_id)
	local conversation = {}
	setmetatable(conversation, molch.conversation)

	local raw_conversation_id = molch_interface.ucstring_array(molch_interface.CONVERSATION_ID_SIZE)
	local raw_packet = molch_interface.create_ucstring_pointer()
	local raw_packet_length = molch_interface.size_t()
	local raw_backup = molch_interface.create_ucstring_pointer()
	local raw_backup_length = molch_interface.size_t()

	local raw_message, raw_message_length = convert_to_c_string(message)
	local raw_prekey_list, raw_prekey_list_length = convert_to_c_string(prekey_list)

	local status = molch_interface.molch_create_send_conversation(
		raw_conversation_id,
		molch_interface.CONVERSATION_ID_SIZE,
		raw_packet,
		raw_packet_length,
		raw_message,
		raw_message_length,
		raw_prekey_list,
		raw_prekey_list_length,
		convert_to_c_string(self.id),
		#self.id,
		convert_to_c_string(receiver_id),
		#receiver_id,
		raw_backup,
		raw_backup_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.free(raw_packet)
		molch_interface.free(raw_backup)
		error(molch.print_errors(status))
	end

	local conversation_id = convert_to_lua_string(raw_conversation_id, molch_interface.CONVERSATION_ID_SIZE)
	raw_packet = copy_callee_allocated_string(raw_packet, raw_packet_length)
	raw_backup = copy_callee_allocated_string(raw_backup, raw_backup_length)

	self.backup = molch.backup.new(raw_backup, raw_backup_length)
	users.attributes.backup = self.backup:copy()

	local packet = convert_to_lua_string(raw_packet, raw_packet_length)
	local backup = convert_to_lua_string(raw_backup, raw_backup_length)

	conversation.backup = molch.backup.new()
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
	local raw_backup = molch_interface.create_ucstring_pointer()
	local raw_backup_length = molch_interface.size_t()

	local raw_packet, raw_packet_length = convert_to_c_string(packet)

	local status = molch_interface.molch_create_receive_conversation(
		raw_conversation_id,
		molch_interface.CONVERSATION_ID_SIZE,
		raw_message,
		raw_message_length,
		raw_packet,
		raw_packet_length,
		raw_prekey_list,
		raw_prekey_list_length,
		convert_to_c_string(sender_id),
		#sender_id,
		convert_to_c_string(self.id),
		#self.id,
		raw_backup,
		raw_backup_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.free(raw_message)
		molch_interface.free(raw_prekey_list)
		molch_interface.free(raw_backup)
		error(molch.print_errors(status))
	end

	local conversation_id = convert_to_lua_string(raw_conversation_id, molch_interface.CONVERSATION_ID_SIZE)
	raw_message = copy_callee_allocated_string(raw_message, raw_message_length)
	raw_prekey_list = copy_callee_allocated_string(raw_prekey_list, raw_prekey_list_length)
	raw_backup = copy_callee_allocated_string(raw_backup, raw_backup_length)

	self.backup = molch.backup.new(raw_backup, raw_backup_length)
	users.attributes.backup = self.backup:copy()

	local message = convert_to_lua_string(raw_message, raw_message_length)
	local prekey_list = convert_to_lua_string(raw_prekey_list, raw_prekey_list_length)

	conversation.backup = molch.backup.new()
	conversation.id = conversation_id
	self.prekey_list = prekey_list

	-- add to the users list of conversations
	self.conversations[conversation_id] = conversation

	return conversation, message
end

function molch.user:get_prekey_list()
	local prekey_list_length = molch_interface.size_t()
	local temp_prekey_list = molch_interface.create_ucstring_pointer()

	local status = molch_interface.molch_get_prekey_list(
		convert_to_c_string(self.id),
		temp_prekey_list,
		prekey_list_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.free(temp_prekey_list)
		error(molch.print_errors(status))
	end

	-- copy the prekey list over to an array managed by swig and free the old
	local raw_prekey_list = copy_callee_allocated_string(temp_prekey_list, prekey_list_length)

	self.prekey_list = convert_to_lua_string(raw_prekey_list, prekey_list_length)

	return self.prekey_list
end

function molch.conversation:encrypt_message(message)
	local raw_message, raw_message_length = convert_to_c_string(message)
	local raw_packet = molch_interface.create_ucstring_pointer()
	local raw_packet_length = molch_interface.size_t()
	local raw_backup = molch_interface.create_ucstring_pointer()
	local raw_backup_length = molch_interface.size_t()

	local status = molch_interface.molch_encrypt_message(
		raw_packet,
		raw_packet_length,
		raw_message,
		raw_message_length,
		convert_to_c_string(self.id),
		#self.id,
		raw_backup,
		raw_backup_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.free(raw_packet)
		molch_interface.free(raw_backup)
		error(molch.print_errors(status))
	end

	raw_packet = copy_callee_allocated_string(raw_packet, raw_packet_length)
	raw_backup = copy_callee_allocated_string(raw_backup, raw_backup_length)

	local packet = convert_to_lua_string(raw_packet, raw_packet_length)
	self.backup = molch.backup.new(raw_backup, raw_packet_length)

	return packet
end

function molch.conversation:decrypt_message(packet)
	local raw_packet, raw_packet_length = convert_to_c_string(packet)
	local raw_message = molch_interface.create_ucstring_pointer()
	local raw_message_length = molch_interface.size_t()
	local raw_backup = molch_interface.create_ucstring_pointer()
	local raw_backup_length = molch_interface.size_t()
	local raw_receive_message_number = molch_interface.size_t()
	local raw_previous_receive_message_number = molch_interface.size_t()

	local status = molch_interface.molch_decrypt_message(
		raw_message,
		raw_message_length,
		raw_packet,
		raw_packet_length,
		convert_to_c_string(self.id),
		raw_receive_message_number,
		raw_previous_receive_message_number,
		raw_backup,
		raw_backup_length)
	local status_type = molch_interface.get_status(status)
	if status_type ~= molch_interface.SUCCESS then
		molch_interface.free(raw_message)
		molch_interface.free(raw_backup)
		error(molch.print_errors(status))
	end

	raw_message = copy_callee_allocated_string(raw_message, raw_message_length)
	raw_backup = copy_callee_allocated_string(raw_backup, raw_backup_length)


	local message = convert_to_lua_string(raw_message, raw_message_length)
	self.backup = molch.backup.new(raw_backup, raw_backup_length)

	return message, raw_receive_message_number:value(), raw_previous_receive_message_number:value()
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

	local raw_backup = molch_interface.create_ucstring_pointer()
	local raw_backup_length = molch_interface.size_t()

	molch_interface.molch_end_conversation(
		convert_to_c_string(self.id),
		raw_backup,
		raw_backup_length)

	raw_backup = copy_callee_allocated_string(raw_backup, raw_backup_length)

	containing_user.backup = molch.backup.new(raw_backup, raw_backup_length)
	users.attributes.backup = containing_user.backup.copy()

	containing_user.conversations[self.id] = nil
	recursively_delete_table(self)
end

function molch.print_errors(status)
	local size = molch_interface.size_t()
	local raw_error_stack = molch_interface.molch_print_status(status, size)
	molch_interface.molch_destroy_return_status(status)
	return raw_error_stack
end

return molch
