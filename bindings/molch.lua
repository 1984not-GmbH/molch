local molch = {}

local molch_interface = require("molch-interface")

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
		count = 0,
		json = ""
	}
}

molch.user = {}
molch.user.__index = molch.user

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

	-- add to global list of users
	users[user.id] = user
	users.attributes.count = users.attributes.count + 1

	return user
end

function molch.user:destroy()
	molch_interface.molch_destroy_user(
		convert_to_c_string(self.id),
		nil,
		nil)

	-- remove from list of users
	users[self.id] = nil
	users.attributes.count = users.attributes.count - 1

	setmetatable(self, nil)
	recursively_delete_table(self)
end

function molch.user_count()
	return users.attributes.count
end
molch.user.count = molch.user_count

function molch.user_list()
	local list = {}
	for user_id, user in pairs(users) do
		if user_id ~= 'attributes' then
			table.insert(list, user_id)
		end
	end

	return list
end
molch.user.list = molch.user_list

function molch.json_export()
	local json_length = molch_interface.size_t()

	local json
	if users.attributes.count == 0 then -- work around ugly bug that makes it crash under some circumstances when using sodium_malloc
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
	local user_list = molch.user_list()

	for _,user_id in ipairs(user_list) do
		users[user_id]:destroy()
	end

	molch_interface.molch_destroy_all_users()

	recursively_delete_table(users)

	users.attributes = {
		count = 0,
		json = ""
	}
end

return molch
