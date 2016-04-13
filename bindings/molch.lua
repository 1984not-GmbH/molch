local molch = {}

local molch_interface = require("molch-interface")

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


molch.user = {}
molch.user.__index = molch.user

function molch.user.new()
	local user = {}
	setmetatable(user, molch.user)

	user.raw_data = {
		id = molch_interface.ucstring_array(32),
		prekey_list = nil,
		prekey_list_length = molch_interface.size_t(),
		json = nil,
		json_length = molch_interface.size_t()
	}

	-- this will be allocated by molch!
	local temp_prekey_list = molch_interface.create_ucstring_pointer()
	local temp_json = molch_interface.create_ucstring_pointer()

	local status = molch_interface.molch_create_user(
		user.raw_data.id,
		temp_prekey_list,
		user.raw_data.prekey_list_length,
		nil,
		0,
		temp_json,
		user.raw_data.json_length
	)
	if status ~= 0 then
		-- TODO free temp_prekey_list
	end

	user.raw_data.prekey_list = molch_interface.ucstring_array(user.raw_data.prekey_list_length:value())
	-- copy the prekey list over to an array managed by swig and free the old
	molch_interface.ucstring_copy(user.raw_data.prekey_list, molch_interface.dereference_ucstring_pointer(temp_prekey_list), user.raw_data.prekey_list_length:value())
	molch_interface.free(molch_interface.ucstring_to_void(temp_prekey_list))


	user.raw_data.json = molch_interface.ucstring_array(user.raw_data.json_length:value())

	-- copy the json over to an array managed by swig and free the old
	molch_interface.ucstring_copy(user.raw_data.json, molch_interface.dereference_ucstring_pointer(temp_json), user.raw_data.json_length:value())
	molch_interface.free(molch_interface.ucstring_to_void(temp_json))

	-- create lua strings from the data
	local id = {}
	for i = 0, 31 do
		table.insert(id, string.char(user.raw_data.id[i]))
	end
	user.id = table.concat(id)

	local prekey_list = {}
	for i = 0, user.raw_data.prekey_list_length:value() - 1 do
		table.insert(prekey_list, string.char(user.raw_data.prekey_list[i]))
	end
	user.prekey_list = table.concat(prekey_list)

	local json = {}
	for i = 0, user.raw_data.json_length:value() - 1 do
		table.insert(json, string.char(user.raw_data.json[i]))
	end
	user.json = table.concat(json)

	return user
end

return molch
