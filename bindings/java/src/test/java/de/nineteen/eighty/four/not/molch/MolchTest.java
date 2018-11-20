package de.nineteen.eighty.four.not.molch;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MolchTest {
	@Test
	@DisplayName("Test that JUnit works")
	void testThatJUnitWorks() {
		assertTrue(true);
	}

	@Test
	@DisplayName("Test getUserIdSize")
	void testGetUserIdSize() {
		assertEquals(32, Molch.getUserIdSize() );
	}
}
