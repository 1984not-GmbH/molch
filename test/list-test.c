/* Molch, an implementation of the axolotl ratchet based on libsodium
 *  Copyright (C) 2015  Max Bruckner (FSMaxB)
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <assert.h>

#include "../lib/list.h"

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	int status;
	list_t *integers = malloc(sizeof(list_t));
	if (integers == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		return EXIT_FAILURE;
	}
	list_init(integers);

	// create a list with numbers from 0 to 9
	for (size_t i = 0; i < 10; i++) {
		int *number = malloc(sizeof(int));
		if (number == NULL) {
			fprintf(stderr, "ERROR: Failed to allocate memory!\n");
			list_clear(integers, free, free);
			free(integers);
			return EXIT_FAILURE;
		}
		*number = i;
		list_node *node = malloc(sizeof(list_node));
		if (node == NULL) {
			fprintf(stderr, "ERROR: Failed to allocate memory!\n");
			free(number);
			list_clear(integers, free, free);
			free(integers);
			return EXIT_FAILURE;
		}
		status = list_add(integers, (void*)number, node);
		if (status != 0) {
			fprintf(stderr, "ERROR: Failed to add entry to list! (%i)\n", status);
			return status;
		}
	}

	//get the 5th element
	list_node *fifth = NULL;
	list_foreach(integers,
			printf("%i\n", *(int*)value);
			if (index == 5) {
				fifth = node;
			}
	);

	//remove the fifth element
	list_remove(integers, fifth, free, free);

	//remove the second element
	list_remove(integers, integers->head->next, free, free);

	if (integers->length != 8) {
		fprintf(stderr, "ERROR: Failed to remove elements, wrong length!\n");
		list_clear(integers, free, free);
		free(integers);
		return EXIT_FAILURE;
	}

	//remove head and tail
	list_remove(integers, integers->head, free, free);
	list_remove(integers, integers->tail, free, free);
	if (integers->length != 6) {
		fprintf(stderr, "ERROR: Failed to remove elements, wrong length!\n");
		list_clear(integers, free, free);
		free(integers);
		return EXIT_FAILURE;
	}

	//copy the list of integers into an array
	int integer_array[6];
	int integer_array_comparison[6] = {2, 3, 4, 6, 7, 8};
	list_foreach(integers,
			printf("%i\n", *(int*)value);
			integer_array[index] = *(int*)value;
	);
	if (sodium_memcmp(integer_array, integer_array_comparison, sizeof(integer_array)) != 0) {
		fprintf(stderr, "ERROR: Removing data failed. Wrong number still remain in the list.\n");
		list_clear(integers, free, free);
		free(integers);
		return EXIT_FAILURE;
	}

	list_clear(integers, free, free);
	free(integers);

	//test list that puts data directly into the nodes
	printf("Test list that contains data in Node.\n");
	list_t *reals = malloc(sizeof(list_t));
	if (reals == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		return EXIT_FAILURE;
	}
	list_init(reals);
	list_node *real_node = malloc(sizeof(list_node) + sizeof(double));
	if (real_node == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		free(reals);
		return EXIT_FAILURE;
	}
	//get a pointer to the data after the list_node struct
	double *content = (double*) (((uint8_t*)real_node) + sizeof(list_node));
	//add the node
	status = list_add(reals, content, real_node);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add node. (%i)\n", status);
		list_clear(reals, free, NULL);
		free(reals);
		return status;
	}
	if ((reals->head != real_node) || (reals->tail != real_node) || (real_node->next != NULL) || (real_node->previous != NULL)) {
		fprintf(stderr, "ERROR: Faield to add node to list. Wrong pointers.\n");
		list_clear(reals, free, NULL);
		free(reals);
		return EXIT_FAILURE;
	}

	list_clear(reals, free, NULL);
	free(reals);

	//test list that has it's data on the stack.
	printf("Test list with data on the stack.\n");
	list_t *strings = malloc(sizeof(list_t));
	if (strings == NULL) {
		fprintf(stderr, "ERROR: Failed to allocate memory!\n");
		return EXIT_FAILURE;
	}
	list_init(strings);
	char *string_array[3] = {
		"Hello ",
		"world!\n",
		"Isn't this nice?\n"
	};
	list_node string_node[3];
	//add all three strings
	status = list_add(strings, string_array[0], &string_node[0]);
	status |= list_add(strings, string_array[1], &string_node[1]);
	status |= list_add(strings, string_array[2], &string_node[2]);
	if (status != 0) {
		fprintf(stderr, "ERROR: Failed to add strings to list. (%i)\n", status);
		list_clear(strings, NULL, NULL);
		free(strings);
		return status;
	}

	list_foreach(strings,
			printf("%s", (char*)value);
	);

	list_clear(strings, NULL, NULL);
	free(strings);

	return EXIT_SUCCESS;
}

