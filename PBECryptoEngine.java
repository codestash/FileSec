
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

import java.io.UnsupportedEncodingException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Logger;

public class PBECryptoEngine 
{
	private byte[] salt = null;
	private static Logger logtool = FileSecConstants.logging;
	
	/***
	 * Encrypt the symmetric key generated using generateSessionKey function
	 * with the password specified on command line. Write the encrypted key
	 * to JarConfig.xml file
	 * 
	 * @param cipherType
	 * @param password
	 * @param sessionkey
	 * @return
	 * @throws FileSecException
	 */
	String encrypt(String cipherType, String password, String sessionkey) throws FileSecException 
	{
		Cipher cipher = setupCipher(Cipher.ENCRYPT_MODE, cipherType, password.toCharArray());
		byte[] cipherText=null;
		try 
		{
			cipherText = cipher.doFinal(sessionkey.getBytes(FileSecConstants.ENCODING));
		} 
		catch (IllegalBlockSizeException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0015,e);
		}
		catch (BadPaddingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0016,e);
		}
		catch (UnsupportedEncodingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019,e); 
		}
		if (logtool != null) logtool.info("Returning encrypted session key prepended with salt");
		return (Base64.encodeBytes(salt)+Base64.encodeBytes(cipherText)); 
	}

	
	/***
	 * On the receiver side, take the encrypted SessionKey from JarConfig.xml,
	 * decrypt it and return it to the File decryption to retrieve original files
	 * 
	 * @param cipherType
	 * @param password
	 * @param text
	 * @return
	 * @throws FileSecException
	 */
	String decrypt(String cipherType, String password, String text) throws FileSecException 
	{
		final int SALT_OFFSET = 12; // salt in first 12 bytes
		Cipher cipher = null;
		byte[] cipherTextBytes = null;;
		try 
		{
		salt = Base64.decode(text.substring(0, SALT_OFFSET));
		// ACTUAL KEY IS ONLY FROM BYTE 12 ONWARDS (1ST 12 BYTES IS ONLY THE SALT)
		cipherTextBytes = Base64.decode(text.substring(SALT_OFFSET, text.length()));
		cipher = setupCipher(Cipher.DECRYPT_MODE, cipherType, password.toCharArray());
		if (logtool != null) logtool.info("PBE DECRYPT RETURNS  "+new String(cipher.doFinal(cipherTextBytes), FileSecConstants.ENCODING));
		return new String(cipher.doFinal(cipherTextBytes), FileSecConstants.ENCODING);

		} 
		catch (UnsupportedEncodingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019,e);
		}
		catch (IllegalBlockSizeException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0015,e);
		}
		catch (BadPaddingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0016,e);
		}
	}

	/***
	 * Setup function to initialize cipher mode, iterations, salt size in bytes
	 * and other init parameters to prepare for encryption / decryption
	 * 
	 * @param mode
	 * @param cipherType
	 * @param password
	 * @return
	 * @throws FileSecException
	 */
	private Cipher setupCipher(int mode, String cipherType,	char[] password) throws FileSecException 
	{
		final int ITERATIONS = 1000;		// 1000 iterations of salt
		final int SALT_SIZE = 8;			// Salt size in bytes
		Cipher cipher= null;
		if (mode == Cipher.ENCRYPT_MODE)
		{
			if (logtool != null) logtool.info("Generating salt of size 8 bytes");
			salt = generateSalt(SALT_SIZE);
		}
		try 
		{
		cipher = Cipher.getInstance(cipherType);
		cipher.init(mode, generatePBEEncryptingKey(cipherType, password), new PBEParameterSpec(salt, ITERATIONS));
		if (logtool != null) logtool.info("Initialized cipher successfully with given parameters");
		}
		catch (InvalidKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0017,e);
		}
		catch (InvalidAlgorithmParameterException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0020,e);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		}
		catch (NoSuchPaddingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0018,e);
		}
		return cipher;
	}

	/***
	 * GENERATE AN 8-BYTE SALT TO PREPEND TO THE ENCRYPTED SESSION KEY
	 * THIS HELPS PREVENT DICTIONARY ATTACKS
	 * @param lengthInBytes
	 * @return
	 */
	private byte[] generateSalt(int lengthInBytes) 
	{
		byte[] salt = new byte[lengthInBytes];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}
	
	/***
	 * Function to generate a PBEeySpec key from the specified password.
	 * This password based key will then be used to encrypt session key.
	 *  
	 * length
	 * @param cipherType
	 * @param password
	 * @return
	 * @throws FileSecException
	 */
	private SecretKey generatePBEEncryptingKey(String cipherType, char[] password) throws FileSecException
	{
		SecretKeyFactory factory;
		try 
		{
			factory = SecretKeyFactory.getInstance(cipherType);
			if (logtool != null) logtool.info("Created a new PBEKeySpec key using the password");
			return factory.generateSecret(new PBEKeySpec(password));
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009,e);
		}
		catch (InvalidKeySpecException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0021,e);
		}
	}
	
	/***
	 * HashPasswords function is written to support the multiple passwords
	 * option for PBE encryption. It accepts the ArrayList of passwords,
	 * hashes them and writes them to XML on sender side. On receiver side
	 * password from command line is hashed and compared to this ArrayList
	 * @param password
	 * @return
	 * @throws FileSecException
	 */
	protected String hashPassword(String password) throws FileSecException // #SSN
    {
        final String charEncoding = FileSecConstants.ENCODING;
        MessageDigest md = null;
		try 
		{
			if (logtool != null) logtool.info("Generating Message digest for passwords using algorithm "+FileSecConstants.hashAlgo);
			md = MessageDigest.getInstance(FileSecConstants.hashAlgo);
			md.update(password.getBytes(charEncoding));
			if (logtool != null) logtool.info("Hashes computed for all passwords");
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009, e);
		}
		catch (UnsupportedEncodingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0022, e);
		}
        byte[] digest = md.digest();
        return Base64.encodeBytes(digest);
        }

}

