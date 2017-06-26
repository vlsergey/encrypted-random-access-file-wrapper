package name.vlsergey.erafw;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.apache.commons.pool2.BasePooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class EncryptedRandomAccessFileWrapperTest {

	private static final int PIECES = 1024;

	private final SecureRandom random = new SecureRandom();

	private final int TEST_DATA_LENGTH = 32 * 1024 * 1024;

	private File testFile;

	@After
	public void after() {
		boolean deleted = this.testFile.delete();
		if (!deleted)
			throw new AssertionError("Temporary file " + testFile + " was not deleted");
	}

	private void assertFileContentEquals(byte[] expected, EncryptedRandomAccessFileWrapper wrapper)
			throws IOException, GeneralSecurityException {
		byte[] whole = new byte[TEST_DATA_LENGTH];
		wrapper.readFully(0, whole);
		Assert.assertArrayEquals(expected, whole);
	}

	@Before
	public void before() throws IOException {
		this.testFile = File.createTempFile("EncryptedRandomAccessFileWrapperTest", ".bin");
	}

	@Test
	public void testRandomWritingsAndReadings() throws IOException, GeneralSecurityException {
		byte[] testData = new byte[TEST_DATA_LENGTH];
		random.nextBytes(testData);

		try (EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper(
				new RandomAccessFile(testFile, "rw"))) {
			// first of all -- write ALL data, so we don't have skips
			wrapper.write(0, testData);

			// rewrite random regions
			for (int t = 0; t < PIECES; t++) {
				int randomOffset = random.nextInt(TEST_DATA_LENGTH - 3);
				randomOffset -= randomOffset % EncryptedRandomAccessFileWrapper.BLOCK_SIZE_IN_BYTES;
				int randomLength = 1 + random.nextInt((TEST_DATA_LENGTH - randomOffset - 1) / PIECES);
				wrapper.write(randomOffset, testData, randomOffset, randomLength);
			}

			assertFileContentEquals(testData, wrapper);

			// reread random regions
			for (int t = 0; t < PIECES; t++) {
				int randomOffset = random.nextInt(TEST_DATA_LENGTH - 3);
				randomOffset -= randomOffset % EncryptedRandomAccessFileWrapper.BLOCK_SIZE_IN_BYTES;
				int randomLength = 1 + random.nextInt((TEST_DATA_LENGTH - randomOffset - 1) / PIECES);

				final byte[] actual = new byte[randomLength];
				wrapper.readFully(randomOffset, actual);

				final byte[] expected = new byte[randomLength];
				System.arraycopy(testData, randomOffset, expected, 0, randomLength);

				Assert.assertArrayEquals(expected, actual);
			}
		}
	}

	@Test
	public void testWithGenericPool() throws IOException, GeneralSecurityException {
		byte[] testData = new byte[TEST_DATA_LENGTH];
		random.nextBytes(testData);

		final GenericObjectPoolConfig config = new GenericObjectPoolConfig();

		final GenericObjectPool<Cipher> cipherPool = new GenericObjectPool<>(new BasePooledObjectFactory<Cipher>() {
			@Override
			public Cipher create() throws Exception {
				return Cipher.getInstance(EncryptedRandomAccessFileWrapper.TRANSFORMATION);
			}

			@Override
			public PooledObject<Cipher> wrap(Cipher cipher) {
				return new DefaultPooledObject<>(cipher);
			}
		}, config);

		try (EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper(
				new RandomAccessFile(testFile, "rw")) {
			@Override
			protected Cipher borrowCipher() {
				try {
					return cipherPool.borrowObject();
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			protected void returnCipher(Cipher cipher) {
				cipherPool.returnObject(cipher);
			};
		}) {
			// first of all -- write ALL data, so we don't have skips
			wrapper.write(0, testData);

			// rewrite random regions
			for (int t = 0; t < PIECES; t++) {
				int randomOffset = random.nextInt(TEST_DATA_LENGTH - 3);
				randomOffset -= randomOffset % EncryptedRandomAccessFileWrapper.BLOCK_SIZE_IN_BYTES;
				int randomLength = 1 + random.nextInt((TEST_DATA_LENGTH - randomOffset - 1) / PIECES);
				wrapper.write(randomOffset, testData, randomOffset, randomLength);
			}

			assertFileContentEquals(testData, wrapper);

			// reread random regions
			for (int t = 0; t < PIECES; t++) {
				int randomOffset = random.nextInt(TEST_DATA_LENGTH - 3);
				randomOffset -= randomOffset % EncryptedRandomAccessFileWrapper.BLOCK_SIZE_IN_BYTES;
				int randomLength = 1 + random.nextInt((TEST_DATA_LENGTH - randomOffset - 1) / PIECES);

				final byte[] actual = new byte[randomLength];
				wrapper.readFully(randomOffset, actual);

				final byte[] expected = new byte[randomLength];
				System.arraycopy(testData, randomOffset, expected, 0, randomLength);

				Assert.assertArrayEquals(expected, actual);
			}

		}

	}

	@Test
	public void testWholeFile() throws IOException, GeneralSecurityException {
		byte[] testData = new byte[TEST_DATA_LENGTH];
		random.nextBytes(testData);

		try (EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper(
				new RandomAccessFile(testFile, "rw"))) {
			// first of all -- write ALL data, so we don't have skips
			wrapper.write(0, testData);

			assertFileContentEquals(testData, wrapper);
		}

	}

}
