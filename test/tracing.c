/*
 * Molch, an implementation of the axolotl ratchet based on libsodium
 *
 * ISC License
 *
 * Copyright (C) 2015-2016 1984not Security GmbH
 * Author: Max Bruckner (FSMaxB)
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
