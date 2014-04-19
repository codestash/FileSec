
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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.logging.Logger;

public class JarSignEngine 
{
	private Signature engine =null;
	private static final Logger logtool = FileSecConstants.logging;
	
	/***
	 * Constructor to create a new instance of JarSignEngine with a user
	 * specified algorithm name and log to file
	 * @param algorithmSuite
	 * @throws FileSecException
	 */
	public JarSignEngine(String algorithmSuite) throws FileSecException
	{
		try 
		{
			if (logtool != null) logtool.info("Instantiating signature engine with algorithm "+algorithmSuite);
			this.engine = Signature.getInstance(algorithmSuite);
		}
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019, e);
		}
	}

	/***
	 * Take a list of input files, read them into a byte[] buffer, generate a Digital
	 * signature over all files(listed in order) using the private key at this alias
	 * in the keystore specified. Write it out to JarConfig.xml file
	 * 
	 * @param filenames
	 * @param alias
	 * @param keystore
	 * @param keypass
	 * @param storepass
	 * @return
	 * @throws FileSecException
	 */
    public String GenerateSignForJAR(ArrayList<String> filenames, String alias,String keystore,
			  								String keypass, String storepass) throws FileSecException
    {
    	Collections.sort(filenames);
		byte[] data = new JarUtil().readFilesIntoBuffer(filenames);
		final String keyStoreName = keystore;
		final char[] keyStorePassword = storepass.toCharArray();
		final char[] entryPassword = keypass.toCharArray();
		byte[] signature = null;
		try 
		{
			if (logtool != null) logtool.info("Reading contents of keystore");
			FileInputStream is = new FileInputStream(keyStoreName);
			KeyStore keyStore = KeyStore.getInstance(FileSecConstants.STORETYPE);
			keyStore.load(is, keyStorePassword);
			is.close();
			Arrays.fill(keyStorePassword, ' ');
			if (logtool != null) logtool.info("Clearing keystore password");
			PrivateKey privateKey;
			privateKey = (PrivateKey) keyStore.getKey(alias, entryPassword);
			Arrays.fill(entryPassword, ' ');
			engine.initSign(privateKey);
			if (logtool != null) logtool.info("Updating byte[] data into Sign engine");
			engine.update(data);
			signature = engine.sign();
			if (logtool != null) logtool.info("Computed Digital Signature using private key at alias");
		} 
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068, e);
		} 
		catch (KeyStoreException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0027, e);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019, e);
		} 
		catch (CertificateException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0028, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0063, e);
		} 
		catch (UnrecoverableKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0029, e);
		} 
		catch (InvalidKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0030, e);
		} 
		catch (SignatureException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0031, e);
		}
		
		String retval = Base64.encodeBytes(signature, Base64.DONT_BREAK_LINES);
		return retval;
    }
    
    /***
     * Lists the contents of the specified jar file, reads their contents into a
     * byte[] buffer, and verifies the digital signature read from JarConfig.xml
     * using the public key at specified alias in keystore
     * @param data
     * @param signature
     * @param alias
     * @param keystore
     * @param keypass
     * @param storepass
     * @return
     * @throws FileSecException
     */
    boolean verifySignForJAR(byte[] data, String signature, String alias, String keystore,
    									String keypass, String storepass) throws FileSecException
    {
		final String keyStoreName = keystore;
		boolean verify = false;
		try
		{
			if (logtool != null) logtool.info("Opening keystore for read");
			FileInputStream is = new FileInputStream(keyStoreName);
			final char[] keyStorePassword = storepass.toCharArray();
			final char[] entryPassword = keypass.toCharArray();
			KeyStore keyStore = KeyStore.getInstance(FileSecConstants.STORETYPE);
			keyStore.load(is, keyStorePassword);
			is.close();
			byte[] sign = Base64.decode(signature, Base64.DONT_BREAK_LINES);
			if (logtool != null) logtool.info("Decoded signature using public key from keystore");
	
			PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
			Arrays.fill(entryPassword, ' ');
			if (logtool != null) logtool.info("Clearing keystore password");
			engine.initVerify(publicKey);
			engine.update(data);
			System.out.println(signature);
			verify = engine.verify(sign);
			if (logtool != null) logtool.info("Digital Signature for jar file verified -- "+verify);
			engine = null;
		} 
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068, e);
		} 
		catch (KeyStoreException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0027, e);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0019, e);
		} 
		catch (CertificateException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0028, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0063, e);
		} 
		catch (InvalidKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0030, e);
		} 
		catch (SignatureException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0031, e);
		}
		engine = null;
		return verify;
    }
}
