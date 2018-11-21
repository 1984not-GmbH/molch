package de.nineteen.eighty.four.not.molch;

import java.util.Optional;

enum MessageType {
	PREKEY,
	NORMAL,
	INVALID,
}


class Molch {
	static {
		System.loadLibrary("molch-jni");
	}

	static class CreateUserResult {
		public byte[] userId;
		public byte[] prekeyList;
		public byte[] backupKey;
		public Optional<byte[]> backup;
	}

	static native long getUserIdSize();
	static native long getConversationIdSize();
	static native long getBackupKeySize();

	static native CreateUserResult createUser(boolean createBackup, Optional<byte[]> randomSpice) throws Exception;
	static native Optional<byte[]> destroyUser(byte[] id, boolean createBackup) throws Exception;
	static native long countUsers();
	static native void destroyAllUsers();
	static native byte[][] listUsers();

	static native MessageType getMessageType(byte[] packet);

	static class SendConversationResult {
		public byte[] conversationId;
		public byte[] packet;
		public Optional<byte[]> backup;
	}

	static native SendConversationResult startSendConversation(
			byte[] senderId,
			byte[] receiverId,
			byte[] prekeyList,
			byte[] message,
			boolean createBackup) throws Exception;

	static class ReceiveConversationResult {
		public byte[] conversationId;
		public byte[] prekeyList;
		public byte[] message;
		public Optional<byte[]> backup;
	}

	static native ReceiveConversationResult startReceiveConversation(
			byte[] receiverId,
			byte[] senderId,
			byte[] packet,
			boolean createBackup) throws Exception;

	static class EncryptResult {
		public byte[] packet;
		public Optional<byte[]> conversationBackup;
	}

	static native EncryptResult encrypt(
			byte[] conversationId,
			byte[] message,
			boolean createConversationBackup) throws Exception;

	static class DecryptResult {
		public long messageNumber;
		public long previousMessageNumber;
		public byte[] message;
		public Optional<byte[]> conversationBackup;
	}

	static native DecryptResult decrypt(
			byte[] conversationId,
			byte[] packet,
			boolean createConversationBackup) throws Exception;

	static native Optional<byte[]> endConversation(byte[] conversationId, boolean createBackup) throws Exception;
	static native byte[][] listConversations(byte[] userId) throws Exception;
	static native byte[] exportConversation(byte[] conversationId) throws Exception;
	static native byte[] importConversation(byte[] conversationBackup, byte[] backupKey) throws Exception;
	static native byte[] exportUsers() throws Exception;
	static native byte[] importUsers(byte[] backup, byte[] backupKey) throws Exception;
	static native byte[] getPrekeyList(byte[] userId) throws Exception;
	static native byte[] updateBackupKey();
}
