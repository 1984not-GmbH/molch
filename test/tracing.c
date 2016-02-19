/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2016  Max Bruckner (FSMaxB)
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 * This file incorporates work by Balau, see https://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/
 */

#ifdef TRACING
#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#define __USE_GNU
#include <dlfcn.h>
#include "tracing.h"

static FILE *trace_file = NULL;
//level of how deeply the function call was nested
static unsigned int current_level = 0;

void trace_begin(void) {
	trace_file = fopen("trace.out", "w");
	if (trace_file != NULL) {
		printf("Writing trace of the execution to \"trace.out\".\n");
	}
}

void trace_end(void) {
	if (trace_file != NULL) {
		fclose(trace_file);
		printf("Trace of execution written to \"trace.out\".\n");
	}
}

void __cyg_profile_func_enter(void *function, void *caller) {
	Dl_info function_info;
	Dl_info caller_info;
	bool function_info_available = dladdr(function, &function_info);
	bool caller_info_available = dladdr(caller, &caller_info);
	if (function_info_available && caller_info_available) {
		printf("%u %s -> %s\n", current_level, caller_info.dli_sname, function_info.dli_sname);
	}

	if ((trace_file != NULL) && function_info_available && caller_info_available) {
		fprintf(trace_file, "%u %s -> %s\n", current_level, caller_info.dli_sname, function_info.dli_sname);
	}

	current_level++;
}

void __cyg_profile_func_exit(void *function, void *caller) {
	current_level--;
	Dl_info function_info;
	Dl_info caller_info;
	bool function_info_available = dladdr(function, &function_info);
	bool caller_info_available = dladdr(caller, &caller_info);
	if (function_info_available && caller_info_available) {
	    printf("%u %s <- %s\n", current_level, caller_info.dli_sname, function_info.dli_sname);
	}

	if ((trace_file != NULL) && function_info_available && caller_info_available) {
		fprintf(trace_file, "%u %s <- %s\n", current_level, caller_info.dli_sname, function_info.dli_sname);
	}
}
#endif
