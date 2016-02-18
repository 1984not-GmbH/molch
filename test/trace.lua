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

local trace_file = "trace.out"

local function print_usage()
	print([[
Usage: trace.lua
	-t|--trace trace_file
		The trace file to postprocess. Defaults to "trace.out"
	-i|--ignore "function_a,function_b"
		A comma separated list of functions to ignore.
	-h|--help
		Print this help.
]])
end

-- parse the command line parameters
local ignore_string
repeat
	if (arg[1] == "-t") or (arg[1] == "--trace") then
		trace_file = arg[2]
		table.remove(arg, 2)
	elseif (arg[1] == "-i") or (arg[1] == "--ignore") then
		ignore_string = arg[2]
		table.remove(arg, 2)
	elseif (arg[1] == "-h") or (arg[1] == "--help") then
		print_usage()
		os.exit(0)
	else
		io.stderr:write("ERROR: Invalid parameter "..string.format("%q", arg[1]).."\n")
		print_usage()
		os.exit(1)
	end
	table.remove(arg, 1)
until #arg == 0

--parse the ignore string
local function ignores(ignore_string) -- iterator that iterates over all ignore strings
	local position = 1

	return function ()
		if position > #ignore_string then
			return nil
		end

		local comma_position = ignore_string:find(",", position, true)
		local ignore
		if comma_position then
			ignore = ignore_string:sub(position, comma_position - 1)
			position = comma_position + 1
		else
			ignore = ignore_string:sub(position)
			position = #ignore_string + 1
		end

		return ignore
	end
end

-- functions that should be ignored
local ignore_list = {}

if ignore_string then
	for ignore in ignores(ignore_string) do
		ignore_list[ignore] = true
	end
end

local pattern = "^(%d+) ([%a_%(%)]+) ([%-<>]+) ([%a_%(%)]+)$"

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
			print((".   "):rep(level)..callee)
		elseif direction == "<-" then
			print((".   "):rep(level)..caller)
		else
			print("> "..line) -- treat as program output
		end
	end
end
