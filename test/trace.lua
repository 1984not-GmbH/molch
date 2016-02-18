#!/usr/bin/env lua

--[[
-- This is a small lua script to convert the output of tracing.c into
-- a somewhat more readable form and be able to filter out some functions
--
--  Copyright (C) 2016  Max Bruckner (FSMaxB)
--
--  This library is free software; you can redistribute it and/or
--  modify it under the terms of the GNU Lesser General Public
--  License as published by the Free Software Foundation; either
--  version 2.1 of the License, or (at your option) any later version.
--
--  This library is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
--  Lesser General Public License for more details.
--
--  You should have received a copy of the GNU Lesser General Public
--  License along with this library; if not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
--]]

local trace_file = arg[1] or "trace.out"

local pattern = "^(%d+) ([%a_%(%)]+) ([%-<>]+) ([%a_%(%)]+)$"

-- functions that should be ignored
local ignore_list = {
	putchar = true
}

local indentation_strings = {
	deepest_level = 0,
	[0] = ""
}
local function indentation_string(level)
	for i = indentation_strings.deepest_level + 1, level do
		indentation_strings[i] = indentation_strings[i - 1] .. ".   "
	end

	return indentation_strings[level]
end

-- go trough the file line by line
for line in io.lines(trace_file) do
	local level, caller, direction, callee = line:match(pattern)

	if not level then -- not a valid trace line, treat as program output
		print("> "..line)
	elseif ignore_list[callee] then
	else
		level = tonumber(level)
		if direction == "->" then
			print(indentation_string(level + 1)..callee)
		elseif direction == "<-" then
			print(indentation_string(level)..caller)
		else
			print("> "..line) -- treat as program output
		end
	end
end
