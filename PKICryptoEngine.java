
/********************************************************************************
 * 		FILESEC - A Digital Rights Management tool								*
 *																				*
 * 		Authors	 -	Rajiv T Mathew												*	
 * 					Shweta Naik													*
 * 																				*
 * 		Johns Hopkins University Information Security Institute					*
 * 		Java Security (650.412)													*
 * 		© 2008																	*
 * 																				*
 ********************************************************************************
 */	

package fileSec;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class PKICryptoEngine 
{
	private static Logger logtool = FileSecConstants.logging;
	
	/***
	 * Retrieve the public key at alias specified in the defined keystore
	 * Use the public key to encrypt the symmetric session key generated
	 * by executionHandler class
	 * 
	 * @param keyStoreName
	 * @param alias
	 * @param keyStorePass
	 * @param entryPass
	 * @return
	 * @throws FileSecException
	 */
	public PublicKey getPublicKey(String keyStoreName, String alias, String keyStorePass, String entryPass) throws FileSecException 
	{
		final char[] keyStorePassword = keyStorePass.toCharArray();
		final char[] entryPassword = entryPass.toCharArray();
		PublicKey publicKey = null;
		try 
		{
			FileInputStream is = new FileInputStream(keyStoreName);
			KeyStore keyStore = KeyStore.getInstance(FileSecConstants.STORETYPE);
			keyStore.load(is, keyStorePassword);
			is.close();
			Arrays.fill(keyStorePassword, ' ');
			if (logtool != null) logtool.info("Clearing keystore passwords");
			publicKey = keyStore.getCertificate(alias).getPublicKey();
			keyStore.getKey(alias, entryPassword);
			if (logtool != null) logtool.info("Returning public key retrieved from keystore");
		} 
		catch (UnrecoverableKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0010,e);
		}
		catch (KeyStoreException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0011,e);
		}
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		}
		catch (CertificateException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0012,e);
		}
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0013,e);
		}
		Arrays.fill(entryPassword, ' ');
		return publicKey;
		
	}
	
	/***
	 * Retrieve the private key at alias specified in the defined keystore
	 * Use the private key to decrypt  the encypted session key read from
	 * JarConfig.xml
	 * 
	 * @param keyStoreName
	 * @param alias
	 * @param keyStorePass
	 * @param entryPass
	 * @return
	 * @throws FileSecException
	 */
	public PrivateKey getPrivateKey(String keyStoreName, String alias, String keyStorePass, String entryPass)throws FileSecException
	{
		final char[] keyStorePassword = keyStorePass.toCharArray();
		final char[] entryPassword = entryPass.toCharArray();
		PrivateKey privateKey ;
		try 
		{
			if (logtool != null) logtool.info("Opening keystore for reading");
			FileInputStream is = new FileInputStream(keyStoreName);
			final String KEYSTORE_TYPE = FileSecConstants.STORETYPE;
			KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
			keyStore.load(is, keyStorePassword);
			if (logtool != null) logtool.info("Loaded contents of keystore at alias");
			is.close();
			Arrays.fill(keyStorePassword, ' ');
			privateKey = (PrivateKey) keyStore.getKey(alias, entryPassword);
			if (logtool != null) logtool.info("Successfully retrieved private key at alias in keystore");
		} 
		catch (UnrecoverableKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0010,e);
		}
		catch (KeyStoreException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0011,e);
		}
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		}
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0014,e);
		}
		catch (CertificateException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0012,e);
		}
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0013,e);
		}
		Arrays.fill(entryPassword, ' ');
		return privateKey;
	}


	/***
	 * Encrypt the generated symmetric session key with public key at alias
	 * found in the keystore. Return the encrypted session key to Execution
	 * Handler, which will write it out to JarConfig.xml
	 * 
	 * @param alias
	 * @param cipherType
	 * @param sessionkey
	 * @param KEYSTORE
	 * @param KEYSTORE_PASSWORD
	 * @param ENTRY_PASSWORD
	 * @return
	 * @throws FileSecException
	 */
	public String encrypt(String alias, String cipherType, String sessionkey, String KEYSTORE,String KEYSTORE_PASSWORD, String ENTRY_PASSWORD) throws FileSecException
	{
		byte[] encryptedKey;
		try 
		{
			Cipher cipher = Cipher.getInstance(cipherType);
			cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(KEYSTORE,alias,KEYSTORE_PASSWORD,ENTRY_PASSWORD));
			encryptedKey = cipher.doFinal(sessionkey.getBytes(FileSecConstants.ENCODING));
			if (logtool != null) logtool.info("Successfully encrypted the session key");
		} 
		catch (IllegalBlockSizeException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0015,e); 
		} 
		catch (BadPaddingException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0016,e);
		}
		catch (InvalidKeyException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0017,e);
		}
		catch (NoSuchAlgorithmException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		}
		catch (NoSuchPaddingException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0018,e);
		}
		catch (UnsupportedEncodingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019,e); 
		}
		return Base64.encodeBytes(encryptedKey, Base64.DONT_BREAK_LINES);
		
	}
	
	/***
	 * Decrypt the encrypted session key string read from JarConfig.xml with
	 * public key at alias found in the keystore. Return the decrypted session
	 * key to Execution Handler, which will use it to decrypt contents of jar
	 * @param alias
	 * @param cipherType
	 * @param encryptedsessionkey
	 * @param KEYSTORE
	 * @param KEYSTORE_PASSWORD
	 * @param ENTRY_PASSWORD
	 * @param SYM_KEY_TYPE
	 * @return
	 * @throws FileSecException
	 */
	public String decrypt(String alias, String cipherType, String encryptedsessionkey, String KEYSTORE,String KEYSTORE_PASSWORD, String ENTRY_PASSWORD, String SYM_KEY_TYPE) throws FileSecException
	{
		byte[] decryptedRawBytes;
		byte[] keyinbytes;
		try
		{
			Cipher cipher = Cipher.getInstance(cipherType);
			keyinbytes = Base64.decode(encryptedsessionkey, Base64.DONT_BREAK_LINES);
			cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(KEYSTORE,alias,KEYSTORE_PASSWORD,ENTRY_PASSWORD));
			if (logtool != null) logtool.info(" Initialized the PKI decryption cipher");
			decryptedRawBytes = cipher.doFinal(keyinbytes);
			return new String(decryptedRawBytes, FileSecConstants.ENCODING);
		} 
		catch (IllegalBlockSizeException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0015,e); 
		} 
		catch (BadPaddingException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0016,e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		} 
		catch (NoSuchPaddingException e)
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0018,e);
		} 
		catch (InvalidKeyException e) 
		{
			throw new  FileSecException(ErrorCodes.ERR_FILESEC_0017,e);
		} 
		catch (UnsupportedEncodingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0022,e); 
		}
	}
}


