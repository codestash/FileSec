
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class JarMACEngine 
{
	
	private static Logger logtool = FileSecConstants.logging;
	/***
	 * Accept a list of files passed by command line Parser and read these files (IN ORDER) into a
	 * byte array. Initialize a new MAC engine to initialize the algorithm and password and compute
	 * the MAC on this byte[] and write the MAC out to JarConfig.xml
	 * @param filenames
	 * @param algorithm
	 * @param password
	 * @return
	 * @throws Exception
	 */
	public String GenerateMACForJar(ArrayList<String> filenames, String algorithm, String password) 
																				throws FileSecException
	{
		// SORT FILE NAMES SO THEY ARE IN ORDER WHILE ADDING TO BYTE ARRAY
		Collections.sort(filenames);
		byte[] buffer = new JarUtil().readFilesIntoBuffer(filenames);
		final String ALGORITHM = algorithm;
		String MacString = "";
		Mac mac;
		try 
		{
			if (logtool != null) logtool.info("Initializing MAC engine with algorithm "+ALGORITHM);
			mac = Mac.getInstance(ALGORITHM);
			final int keyLengthInBits = FileSecConstants.macKeyLength;		// MAC key length
			mac.init(generateKey(ALGORITHM, keyLengthInBits, password));	// Generate MAC key
			mac.update(buffer, 0, buffer.length);							// Update byte[] into mac engine
			byte[] MacContents = mac.doFinal();								// Compute MAC
			MacString = Base64.encodeBytes(MacContents, Base64.DONT_BREAK_LINES);
			if (logtool != null) logtool.info("Computed MAC for all files ");
			mac = null;
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0064, e);
		} 
		catch (InvalidKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0066, e);
		} 
		return MacString;
	}

	/***
	 * Generate a secure MAC key with password and algorithm specified and return it
	 * to the GenerateMACForJar() function call
	 * @param algorithm
	 * @param keyLengthInBits
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private SecretKey generateKey(String algorithm, int keyLengthInBits, String password) throws FileSecException
 
	{
		KeyGenerator kg;
		SecretKey key = null;
		try 
		{
			if (logtool != null) logtool.info("Generating "+algorithm+" symmetric key");
			kg = KeyGenerator.getInstance(algorithm);
			kg.init(keyLengthInBits);
			key = new SecretKeySpec(password.getBytes(), algorithm);
		} 
		catch (NoSuchAlgorithmException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0064, e);
		}
		return key;
	}

	/***
	 * At the receiver end, read out the contents 
	 * @param contents
	 * @param password
	 * @param hashFromXML
	 * @param localparams
	 * @param filenames
	 * @return
	 * @throws Exception
	 */
	public boolean verifyMACForJar(String password, String hashFromXML, HashMap<String, String>
									localparams, ArrayList<String> filenames ) throws FileSecException
	{
		// SORT FILES ON RECEIVER END TOO TO ENSURE SAME ORDER IS MAINTAINED
		Collections.sort(filenames);
		String algorithm = localparams.get("MACHashAlgorithm");						// Algorithm from cmd-line
		if (logtool != null) logtool.info("Regenerating MAC on receiver end to verify jar file");
		String recalculatedHash=GenerateMACForJar(filenames,algorithm, password); 	// REGENERATE MAC on filelist
		// Compare hash read from XML with regenerated MAC of files extracted from jar
		if (hashFromXML.equals(recalculatedHash))
		{
			if (logtool != null) logtool.info("SUCCESS - Hashes match (JAR file verified ");
			return true;
		}
		else
		{
			if (logtool != null) logtool.info("ERROR - Hashes dont match (Jar file is invalid)");
		}
		return false;
		
	}
}
