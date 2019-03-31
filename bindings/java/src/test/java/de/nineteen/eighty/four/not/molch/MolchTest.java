package de.nineteen.eighty.four.not.molch;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Time;
import java.util.Arrays;
import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.IsNull.notNullValue;

class MolchTest {
	@BeforeEach
	void destroyAllUsers() {
		Molch.destroyAllUsers();
	}

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

	@Test
	@DisplayName("Test createUser with spice")
	void testCreateUserWithSpice() throws Exception {
		// Ensure that the native library is loaded
		assertThat(Molch.getBackupKeySize(), is(32L));

		byte[] aliceSpice = {0x6d, 0x6f, 0x6c, 0x63, 0x68};

		long beforeAlice = System.currentTimeMillis();
		Molch.CreateUserResult aliceResult = Molch.createUser(aliceSpice);
		long afterAlice = System.currentTimeMillis();
		assertThat(aliceResult, is(notNullValue()));

		long beforeBob = System.currentTimeMillis();
		Molch.CreateUserResult bobResult = Molch.createUser(null);
		long afterBob = System.currentTimeMillis();
		assertThat(bobResult, is(notNullValue()));

		assertThat(afterAlice - beforeAlice, is(greaterThan(50L)));
		assertThat(afterAlice - beforeAlice, is(greaterThan(2 * (afterBob - beforeBob))));
	}

	@Test
	@DisplayName("Test countUsers")
	void testCountUsers() throws Exception {
		assertThat(Molch.countUsers(), is(0L));
		Molch.CreateUserResult alice = Molch.createUser(null);
		assertThat(Molch.countUsers(), is(1L));
		Molch.CreateUserResult bob = Molch.createUser(null);
		assertThat(Molch.countUsers(), is(2L));
	}

	@Test
	@DisplayName("Test destroyAllUsers")
	void testDestroyAllUsers() throws Exception {
		Molch.destroyAllUsers();
		assertThat(Molch.countUsers(), is(0L));
		Molch.CreateUserResult alice = Molch.createUser(null);
		assertThat(Molch.countUsers(), is(1L));
		Molch.destroyAllUsers();
		assertThat(Molch.countUsers(), is(0L));
	}

	@Test
	@DisplayName("Test getPrekeyListExpirationDateSeconds")
	void testGetPrekeyListExpirationDateSeconds() throws Exception {
		long currentTime = new Date().getTime() / 1000;
		final long oneMonth = 3600 * 24 * 30;

		Molch.CreateUserResult user = Molch.createUser(null);
		long[] expirationDates = Molch.getPrekeyListExpirationDateSeconds(user.userId);

		assertThat(expirationDates.length, is(100));
		for (long expirationDate : expirationDates) {
			assertThat(expirationDate, is(greaterThanOrEqualTo(currentTime + oneMonth)));
		}
	}
}
