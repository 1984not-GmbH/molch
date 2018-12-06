package de.nineteen.eighty.four.not.molch;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsNull.notNullValue;

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

	@Test
	@DisplayName("Test createUser without backup and spice")
	void testCreateUser() throws Exception {
		Molch.CreateUserResult aliceResult = Molch.createUser(false, Optional.empty());

		assertThat(aliceResult, is(notNullValue()));

		assertThat(aliceResult.userId, is(notNullValue()));
		assertThat(aliceResult.userId.length, is(32));

		assertThat(aliceResult.backupKey, is(notNullValue()));
		assertThat(aliceResult.backupKey.length, is(32));

		assertThat(Arrays.equals(aliceResult.userId, aliceResult.backupKey), is(false));

		assertThat(aliceResult.backup, is(Optional.empty()));

		Molch.CreateUserResult bobResult = Molch.createUser(false, Optional.empty());
		assertThat(Arrays.equals(aliceResult.userId, bobResult.userId), is(false));
		assertThat(Arrays.equals(aliceResult.backupKey, bobResult.backupKey), is(false));
		assertThat(bobResult.backup, is(Optional.empty()));
	}
}
