# Encrypted RandomAccessFile Wrapper
Wrapper around Java RandomAccessFile to allow encryption (and description) on fly in CTR mode

## Usage

To read and wirte data one need to instantiate EncryptedRandomAccessFileWrapper with RandomAccessFile and use read() and write() methods:

```java

	// Init with random keys and IV (file can be read only until ERAFW is available)
	EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper( randomAccessFile );
	
	// Provide previously stored key and nonce+IV bytes
	// nonce+IV bytes should be 96 bytes long
	// see https://tools.ietf.org/html/rfc3686#section-4
	EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper( randomAccessFile , key, nonceAndIvBytes);
	
	// write bytes at some position
	wrapper.write( position, bs );
	wrapper.write( position, bs, off, len );
	
	// read bytes from some position
	int read;
	read = wrapper.read( position, bs );
	read = wrapper.read( position, bs, off, len );
	read = wrapper.readFully( position, bs );
	read = wrapper.readFully( position, bs, off, len );
	
	// Create CipherInputStream to read data from file
	Cipher cipher = Cipher.getInstance(EncryptedRandomAccessFileWrapper.TRANSFORMATION);
	wrapper.initCipher(Cipher.DECRYPT_MODE, 0);
	try (FileInputStream fis = new FileInputStream(...);
	        CipherInputStream inputStream = new CipherInputStream(fis, cipher) ) {
	    // read data from inputStream
	}

```

## Performance question

Would you need performance you should use Cipher objects pooling. The following example uses Apache commons-pool2:

```java

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
	}, new GenericObjectPoolConfig());
	
	EncryptedRandomAccessFileWrapper wrapper = new EncryptedRandomAccessFileWrapper(
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
	}

```