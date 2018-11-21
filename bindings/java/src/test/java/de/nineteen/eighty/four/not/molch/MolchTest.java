package de.nineteen.eighty.four.not.molch;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.*;

class MolchTest {
	@Test
	@DisplayName("Test that JUnit works")
	void testThatJUnitWorks() {
	    assertThat(true, is(true));
	}

	@Test
	@DisplayName("Test getUserIdSize")
	void testGetUserIdSize() {
		assertThat(Molch.getUserIdSize(), is(32L));
	}

	@Test
	@DisplayName("Test getConversationIdSize")
	void testGetConversationIdSize() {
	    assertThat(Molch.getConversationIdSize(), is(32L));
	}

	@Test
	@DisplayName("Test getBackupKeySize")
	void testGetBackupKeySize() {
		assertThat(Molch.getBackupKeySize(), is(32L));
	}
}
