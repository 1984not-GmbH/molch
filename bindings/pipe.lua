local pipe = {}

local base64 = require("base64")

local read_pipe
local write_pipe

function pipe.create()
	os.execute("mkfifo alice2bob")
	os.execute("mkfifo bob2alice")
end

function pipe.delete()
	os.execute("rm alice2bob")
	os.execute("rm bob2alice")
end

function pipe.open(person)
	local write_path, read_path
	if person == "alice" then
		read_pipe = io.open("bob2alice", "r")
		write_pipe = io.open("alice2bob", "w")
	elseif person == "bob" then
		write_pipe = io.open("bob2alice", "w")
		read_pipe = io.open("alice2bob", "r")
	else
		error(string.format("Unknown person %q", person))
	end

	write_pipe:setvbuf("line")
end

function pipe.send(data)
	local line = base64.encode(data) .. "\n"
	write_pipe:write(line)
end

function pipe.receive()
	local line = read_pipe:read("*l")
	return base64.decode(line)
end

return pipe
