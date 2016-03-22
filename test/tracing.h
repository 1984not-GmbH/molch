/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015-2016 1984not Security GmbH
 *  Author: Max Bruckner (FSMaxB)
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

//This enables the creation of traces for debug purposes

#ifdef TRACING

#ifndef TEST_TRACING
#define TEST_TRACING
void trace_begin(void) __attribute__((constructor)) __attribute__((no_instrument_function));
void trace_end(void) __attribute__((destructor)) __attribute__((no_instrument_function));
void __cyg_profile_func_enter(void *function, void *caller) __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *function, void *caller) __attribute__((no_instrument_function));
#endif

#endif
