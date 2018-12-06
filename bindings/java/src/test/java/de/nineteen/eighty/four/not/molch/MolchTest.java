package de.nineteen.eighty.four.not.molch;

import org.hamcrest.Matchers;
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
		Molch.CreateUserResult aliceResult = Molch.createUser(null);

		assertThat(aliceResult, is(notNullValue()));

		assertThat(aliceResult.userId, is(notNullValue()));
		assertThat(aliceResult.userId.length, is(32));

		assertThat(aliceResult.backupKey, is(notNullValue()));
		assertThat(aliceResult.backupKey.length, is(32));

		assertThat(Arrays.equals(aliceResult.userId, aliceResult.backupKey), is(false));

		assertThat(aliceResult.backup, is(notNullValue()));
		assertThat(aliceResult.backup.length, is(greaterThan(0)));

		assertThat(aliceResult.prekeyList, is(notNullValue()));
		assertThat(aliceResult.prekeyList.length, is(not(0)));

		Molch.CreateUserResult bobResult = Molch.createUser(null);
		assertThat(Arrays.equals(aliceResult.userId, bobResult.userId), is(false));
		assertThat(Arrays.equals(aliceResult.prekeyList, bobResult.prekeyList), is(false));
		assertThat(Arrays.equals(aliceResult.backupKey, bobResult.backupKey), is(false));
		assertThat(Arrays.equals(aliceResult.backup, bobResult.backup), is(false));
	}
}
