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
