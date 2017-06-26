package name.vlsergey.erafw;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>
 * Wrapper around {@link RandomAccessFile} that encrypts all read and write
 * operations with it.
 * 
 * <p>
 * By default creates internal key and internal (random) IV. For out-of-session
 * usage one need to provide key and nonce+iv from external storage for each
 * file.
 * 
 * <p>
 * Would you need to read data from file {@link CipherInputStream} can be used:
 * 
 * <pre>
 * EncryptedRandomAccessFileWrapper wrapper = (...previously used one...);
 * Cipher cipher = Cipher.getInstance(EncryptedRandomAccessFileWrapper.TRANSFORMATION);
 * wrapper.initCipher(Cipher.DECRYPT_MODE, 0);
 * try (FileInputStream fis = new FileInputStream(...);
 *         CipherInputStream inputStream = new CipherInputStream(fis, cipher) ) {
 *     // read data from inputStream
 * }
 * </pre>
 * 
 * @author Sergey Vladimirov (vlsergey {at} gmail {dot} com)
 */
public class EncryptedRandomAccessFileWrapper implements Closeable {

	public static final int AES_BLOCK_SIZE_IN_BITS = 128;

	public static final String ALGORITHM_AES = "AES";

	public static final int BLOCK_SIZE_IN_BYTES = AES_BLOCK_SIZE_IN_BITS / 8;

	public static final int INTERNAL_IV_LENGTH_IN_BYTES = 8;

	public static final int NONCE_LENGTH_IN_BYTES = 4;

	public static final int TOTAL_IV_LENGTH_IN_BYTES = 16;

	public static final String TRANSFORMATION = "AES/CTR/NoPadding";

	private final RandomAccessFile file;

	private final Key key;

	private final byte[] nonceAndIv;

	public EncryptedRandomAccessFileWrapper(RandomAccessFile file) {
		this.file = file;
		this.key = createRandomKey();
		this.nonceAndIv = createRandomNonceAndIv();
	}

	public EncryptedRandomAccessFileWrapper(RandomAccessFile file, Key key, byte[] nonceAndIv) {
		this.file = file;
		this.key = key;
		this.nonceAndIv = nonceAndIv;
	}

	private void assertPositionIsMultilierOfBlockSize(long position) {
		if (position % BLOCK_SIZE_IN_BYTES != 0) {
			throw new UnsupportedOperationException("Position need to be multiplier of " + BLOCK_SIZE_IN_BYTES);
		}
	}

	/**
	 * Get cipher from pool (if pool is used) or create it on fly.
	 * 
	 * Cipher <b>must be</b> with counter mode compatible with
	 * https://tools.ietf.org/html/rfc3686#section-4
	 */
	protected Cipher borrowCipher() throws GeneralSecurityException {
		return Cipher.getInstance(TRANSFORMATION);
	}

	private long calculateBlockIndex(long position) {
		assertPositionIsMultilierOfBlockSize(position);
		return position / BLOCK_SIZE_IN_BYTES;
	}

	public void close() throws IOException {
		file.close();
	}

	private Key createRandomKey() {
		final byte[] bs = new byte[BLOCK_SIZE_IN_BYTES];
		new SecureRandom().nextBytes(bs);
		return new SecretKeySpec(bs, ALGORITHM_AES);
	}

	private byte[] createRandomNonceAndIv() {
		byte[] bs = new byte[NONCE_LENGTH_IN_BYTES + INTERNAL_IV_LENGTH_IN_BYTES];
		new SecureRandom().nextBytes(bs);
		return bs;
	}

	public RandomAccessFile getFile() {
		return file;
	}

	/**
	 * Initialize cipher with given opMode so it can be used to start writing or
	 * reading at specified position
	 */
	public void initCipher(final Cipher cipher, int opMode, final long position)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		final long blockIndex = calculateBlockIndex(position);
		final IvParameterSpec ivParameterSpec = newIvParameterSpec(this.nonceAndIv, blockIndex);
		cipher.init(opMode, key, ivParameterSpec);
	}

	private IvParameterSpec newIvParameterSpec(byte[] nonceAndIv, long blockIndex) {
		final ByteBuffer buf = ByteBuffer.allocate(TOTAL_IV_LENGTH_IN_BYTES);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putLong(8, blockIndex);

		// rewrite left bits of blockIndex
		buf.position(0);
		buf.put(nonceAndIv);

		return new IvParameterSpec(buf.array());
	}

	public int read(long position, byte[] b) throws IOException, GeneralSecurityException {
		return read(position, b, 0, b.length);
	}

	public int read(long position, byte[] b, int off, int len) throws IOException, GeneralSecurityException {
		assertPositionIsMultilierOfBlockSize(position);
		file.seek(position);

		byte[] inputBuffer = new byte[len];
		int read = file.read(inputBuffer, 0, len);
		if (read <= 0)
			return read;

		final Cipher cipher = borrowCipher();
		try {
			initCipher(cipher, Cipher.DECRYPT_MODE, position);
			return cipher.doFinal(inputBuffer, 0, read, b);
		} finally {
			returnCipher(cipher);
		}
	}

	/**
	 * Reads {@code b.length} bytes from this file into the byte array, starting
	 * at the current file pointer. This method reads repeatedly from the file
	 * until the requested number of bytes are read. This method blocks until
	 * the requested number of bytes are read, the end of the stream is
	 * detected, or an exception is thrown.
	 */
	public final void readFully(long position, byte b[]) throws IOException, GeneralSecurityException {
		readFully(position, b, 0, b.length);
	}

	/**
	 * Reads exactly {@code len} bytes from this file into the byte array,
	 * starting at the current file pointer. This method reads repeatedly from
	 * the file until the requested number of bytes are read. This method blocks
	 * until the requested number of bytes are read, the end of the stream is
	 * detected, or an exception is thrown.
	 */
	public void readFully(long position, byte b[], int off, int len) throws IOException, GeneralSecurityException {
		int n = 0;
		do {
			int count = this.read(position + n, b, off + n, len - n);
			if (count < 0)
				throw new EOFException();
			n += count;
		} while (n < len);
	}

	protected void returnCipher(Cipher cipher) {
		// return cipher to pool is pool is used
	}

	public void write(long position, byte[] b) throws IOException, GeneralSecurityException {
		write(position, b, 0, b.length);
	}

	public void write(long position, byte[] b, int off, int len) throws IOException, GeneralSecurityException {
		assertPositionIsMultilierOfBlockSize(position);
		file.seek(position);

		byte[] outputBuffer = new byte[len];
		int written;

		final Cipher cipher = borrowCipher();
		try {
			initCipher(cipher, Cipher.ENCRYPT_MODE, position);
			written = cipher.doFinal(b, off, len, outputBuffer);
		} finally {
			returnCipher(cipher);
		}

		file.write(outputBuffer, 0, written);
	}

}
