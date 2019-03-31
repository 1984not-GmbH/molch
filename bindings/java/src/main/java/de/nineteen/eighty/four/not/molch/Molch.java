package de.nineteen.eighty.four.not.molch;

enum MessageType {
	PREKEY,
	NORMAL,
	INVALID,
}


abstract class Molch {
	static {
		System.loadLibrary("molch-jni");
	}

	static native long getUserIdSize();
	static native long getConversationIdSize();
	static native long getBackupKeySize();

	static class CreateUserResult {
		public byte[] userId;
		public byte[] prekeyList;
		public byte[] backupKey;
		public byte[] backup;
	}

	static native CreateUserResult createUser(byte[] randomSpice /* optional */) throws Exception;
	static byte[] destroyUser(byte[] id, boolean createBackup) throws Exception { /* optionaly returns backup */
		throw notImplemented();
	}
	static native long countUsers();
	static native void destroyAllUsers();
	static byte[][] listUsers() throws Exception {
		throw notImplemented();
	}

	static MessageType getMessageType(byte[] packet) {
		throw notImplemented();
	}

	static class SendConversationResult {
		public byte[] conversationId;
		public byte[] packet;
		public byte[] backup;
	}

	static SendConversationResult startSendConversation(
			byte[] senderId,
			byte[] receiverId,
			byte[] prekeyList,
			byte[] message,
			boolean createBackup) throws Exception {
		throw new UnsupportedOperationException("Not implemented yet.");
	}

	static class ReceiveConversationResult {
		public byte[] conversationId;
		public byte[] prekeyList;
		public byte[] message;
		public byte[] backup;
	}

	static ReceiveConversationResult startReceiveConversation(
			byte[] receiverId,
			byte[] senderId,
			byte[] packet,
			boolean createBackup) throws Exception {
		throw new UnsupportedOperationException("Not implemented yet.");
	}

	static class EncryptResult {
		public byte[] packet;
		public byte[] conversationBackup;
	}

	static native EncryptResult encrypt(
			byte[] conversationId,
			byte[] message,
			boolean createConversationBackup) throws Exception;

	static class DecryptResult {
		public long messageNumber;
		public long previousMessageNumber;
		public byte[] message;
		public byte[] conversationBackup;
	}

	static DecryptResult decrypt(
			byte[] conversationId,
			byte[] packet,
			boolean createConversationBackup) throws Exception {
		throw notImplemented();
	}

	static byte[] endConversation(byte[] conversationId, boolean createBackup) throws Exception {
		throw notImplemented();
	}
	static byte[][] listConversations(byte[] userId) throws Exception {
		throw notImplemented();
	}
	static byte[] exportConversation(byte[] conversationId) throws Exception {
		throw notImplemented();
	}
	static byte[] importConversation(byte[] conversationBackup, byte[] backupKey) throws Exception {
		throw notImplemented();
	}
	static byte[] exportUsers() throws Exception {
		throw notImplemented();
	}
	static byte[] importUsers(byte[] backup, byte[] backupKey) throws Exception {
		throw notImplemented();
	}
	static byte[] getPrekeyList(byte[] userId) throws Exception {
		throw notImplemented();
	}
	static native long[] getPrekeyListExpirationDateSeconds(byte[] userId);
	static byte[] updateBackupKey() {
		throw notImplemented();
	}

	private static UnsupportedOperationException notImplemented() {
		throw new UnsupportedOperationException("Not implemented yet.");
	}
}
