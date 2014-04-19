
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

import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ExecutionHandler 
{

		// DEFINE LIST OF HASHMAPS TO HOLD ARGUMENTS AND CALL DESIGNATED FUNCTIONS
		private  ArrayList<String> 		FILE_LIST 		= new ArrayList<String>();
		private HashMap<String, Object> argsmap 		= new HashMap<String, Object>();
		private HashMap<String, String> localparams 	= new HashMap<String, String>();
		private HashMap<String, Object> jarinparams 	= new HashMap<String, Object>();
		private HashMap<String, Object> jaroutparams 	= new HashMap<String, Object>();
		private Logger logtool = FileSecConstants.logging;
		
	/***
	 * Constructor that accepts the argsmap HashMap as input
	 * @param argsfromCmdline
	 */
	public ExecutionHandler(HashMap<String, Object> argsfromCmdline)
	{
		if (logtool != null) logtool.info("Inside ExecutionHandler constructor");
		argsmap = argsfromCmdline;
	}
	
	@SuppressWarnings("unchecked")
	public void executeCommand() throws FileSecException
	{
		/***
		 * Retrieve parameters for jar file from the command line and where
		 * applicable, override default parameters defined at initialization
		 */
		if (argsmap.containsKey(FileSecConstants.jar))			FileSecConstants.JAR_FILE 	= (String)argsmap.get(FileSecConstants.jar);
		if (argsmap.containsKey(FileSecConstants.config))		FileSecConstants.LOCALCONFIG = (String)argsmap.get(FileSecConstants.config);
		if (argsmap.containsKey(FileSecConstants.keystore))		FileSecConstants.KEYSTORE 	= (String)argsmap.get(FileSecConstants.keystore);
		if (argsmap.containsKey(FileSecConstants.storepass))	FileSecConstants.STOREPASS 	= (String)argsmap.get(FileSecConstants.storepass);
		if (argsmap.containsKey(FileSecConstants.keypass))		FileSecConstants.KEYPASS 	= (String)argsmap.get(FileSecConstants.keypass);
		if (argsmap.containsKey(FileSecConstants.files))		FILE_LIST	= (ArrayList<String>)argsmap.get(FileSecConstants.files);
		
		XMLWriter xml = new XMLWriter();
		JarUtil jar = new JarUtil();

		/********************************************************************************
		 * 
		 * SENDER SIDE OPERATIONS - On sender side, the user has the option of performing
		 * the following operations, designated by flags on the command line:
		 * 
		 * 			1. ENCRYPT (PKI)	---->  -ec
		 * 			2. ENCRYPT (PBE)	---->  -ep
		 * 			3. DIGITAL SIGN		---->  -sign
		 * 			4. MAC				---->  -mac
		 * 
		 ********************************************************************************
		 */
		if (argsmap.containsKey(FileSecConstants.sign) || argsmap.containsKey(FileSecConstants.mac)
		   || argsmap.containsKey(FileSecConstants.ec) || argsmap.containsKey(FileSecConstants.ep))
		{
				if (logtool != null) logtool.info("ON SENDER SIDE ");
				// read contents of LocalConfig.xml into the HashMap localparams
				xml.readLocalConfigXML(FileSecConstants.LOCALCONFIG, localparams);
				// write jar creation timestamp into HashMap jaroutparams
				SimpleDateFormat fm = new SimpleDateFormat(FileSecConstants.dateformat);
				jaroutparams.put("CreationTime",fm.format(new Date()));
				if (logtool != null) logtool.info("JAR Created at "+new Date());
				// check which of the flags has been specified on the command line
				
				if (argsmap.containsKey(FileSecConstants.notBefore))	jaroutparams.put("NotBefore", argsmap.get(FileSecConstants.notBefore));
				if (argsmap.containsKey(FileSecConstants.notAfter))		jaroutparams.put("NotAfter", argsmap.get(FileSecConstants.notAfter));
				if (argsmap.containsKey(FileSecConstants.sign))			signFiles();
				if (argsmap.containsKey(FileSecConstants.mac))			macFiles ();
				if (argsmap.containsKey(FileSecConstants.ep))			encryptPBE();
				if (argsmap.containsKey(FileSecConstants.ec))			encryptPKI();
				
				if ( argsmap.containsKey(FileSecConstants.ec) || argsmap.containsKey(FileSecConstants.ep))
				{
					/***
					 * This implies that the user has requested for some form of 
					 * encryption (PKI/PBE). Next steps would involve:
					 * 
					 * 		1. Generating Initialization Vector (IV)
					 * 		2. Reading the sessionKey generated by encrypt function
					 * 		3. Encrypt session key using PKI/PBE cipher
					 * 		4. Write encrypted session key to JarConfig.xml
					 * 		5. Create encrypted jar file
					 */
					
					if (logtool != null) logtool.info(" ENCRYPTION requested");
					String ciphertype = localparams.get("SymmetricCipher");
					int ivLen = Integer.parseInt(localparams.get("SymmetricIVSize"));
					if (logtool != null) logtool.info("Generating IV of size "+ivLen);
					IvParameterSpec ivparam = generateInitializationVector(ivLen);
					if (logtool != null) logtool.info("Writing to JarConfig.xml in jar file");
					xml.writeJarConfigFile(jaroutparams);
					
					SecretKey sessionkey = null;
					if(argsmap.containsKey(FileSecConstants.ec))
						sessionkey = (SecretKey)jaroutparams.get("PKISessionKey");
					else if(argsmap.containsKey(FileSecConstants.ep))
						sessionkey = (SecretKey)jaroutparams.get("PBESessionKey");
	
					if (logtool != null) logtool.info("Creating an encrypted jar file");
					jar.createEncryptedJarFile(FileSecConstants.JAR_FILE, ciphertype, sessionkey, ivparam, (ArrayList<String>)argsmap.get(FileSecConstants.files));
				}
				else
				{
					/***
					 * 	OK - so user does not want any confidentiality options
					 *  in his jar file container. We will write the files into
					 *  a simple jar file and exit.
					 */
					
					if (logtool != null) logtool.info("No encryption options specified");
					if (logtool != null) logtool.info("Writing to JarConfig.xml in jar file");
					xml.writeJarConfigFile(jaroutparams);
					if (logtool != null) logtool.info("Creating a simple jar file");
					jar.createJarFile(FileSecConstants.JAR_FILE, (ArrayList) argsmap.get(FileSecConstants.files));
				}
				
				if (logtool != null) logtool.info("CLEANING UP RESIDUAL ENCRYPTED FILES ON SENDER SIDE");
				cleanupResidualFiles(jar.listJarContents(FileSecConstants.JAR_FILE));
		}

		
		/********************************************************************************
		 * 
		 * RECEIVER SIDE OPERATIONS - On sender side,  user has the option of performing
		 * the following operations, designated by flags on the command line:
		 * 
		 * 			1. DECRYPT (PKI)	---->  -dc
		 * 			2. DECRYPT (PBE)	---->  -dp
		 * 			3. VERIFY  SIGN		---->  -signVerify
		 * 			4. VERIFY  MAC		---->  -macVerify
		 * 
		 ********************************************************************************
		 */		
		
		else if (argsmap.containsKey(FileSecConstants.signVerify) || argsmap.containsKey(FileSecConstants.dc) 
				|| argsmap.containsKey(FileSecConstants.macVerify)|| argsmap.containsKey(FileSecConstants.dp))
		{
				// Extract and read JarConfig.xml from the jar file
				if (logtool != null) logtool.info("Extracting JarConfig.xml from JAR file");
				jar.extractFilesFromJarFile(FileSecConstants.JAR_FILE, FileSecConstants.JARCONFIG);
				xml.readJarConfigXML(FileSecConstants.JARCONFIG, jarinparams);
				
				// Read and parse LocalConfig.xml from receivers local folder
				xml.readLocalConfigXML(FileSecConstants.LOCALCONFIG, localparams);
					
				if (jarinparams.containsKey("BeforeTime"))		verifyNotBefore((String)jarinparams.get("BeforeTime"));
				if (jarinparams.containsKey("AfterTime"))		verifyNotAfter((String)jarinparams.get("AfterTime"));
				if (argsmap.containsKey(FileSecConstants.dp))	decryptPBE();
				if (argsmap.containsKey(FileSecConstants.dc))	decryptPKI();

				if ( argsmap.containsKey(FileSecConstants.dc) || argsmap.containsKey(FileSecConstants.dp))
				{
					/***
					 * This implies that the user has requested for some form of 
					 * decryption (PKI/PBE). Next steps would involve:
					 * 
					 * 		1. Reading Initialization Vector (IV) from JarConfig.xml
					 * 		2. Decrypting the sessionKey from JarConfig.xml
					 * 		3. Using the decrypted key along with IV to decrypt and
					 * 		   extract files form the jar
					 * 		5. Create encrypted jar file
					 */
					if (logtool != null) logtool.info("Decryption operation requested on jar");
					SecretKey sessionkey = null;
					String decryptsessionkey = null;
					String ciphertype = localparams.get("SymmetricCipher");

					if (argsmap.containsKey(FileSecConstants.dc))
						decryptsessionkey = (String)jarinparams.get("DecryptedPKISessionKey");
					else if (argsmap.containsKey(FileSecConstants.dp))
						decryptsessionkey = (String)jarinparams.get("DecryptedPBESessionKey");
					
					if (logtool != null) logtool.info("Decrypting session key from JarConfig.xml");
					sessionkey = new SecretKeySpec(decryptsessionkey.getBytes(), localparams.get("SymmetricKeyType"));
					
					// READ AND Base-64 DECODE THE IV FROM XML
					String ivFromXML = (String)jarinparams.get("IV");
					byte[] iv = Base64.decode(ivFromXML);
					IvParameterSpec ivParam = new IvParameterSpec(iv);
					
					jar.extractFilesFromJarFile(FileSecConstants.JAR_FILE, FileSecConstants.ALLFILES);
					if (logtool != null) logtool.info("Extracted contents of jar to local directory");
					jar.decryptJarContents(FileSecConstants.JAR_FILE, ciphertype, ivParam, sessionkey);
					if (logtool != null) logtool.info("Successfully decrypted contents of jar file");

				}
				else
				{
					if (logtool != null) logtool.info("Successfully extracted contents of simple jar file");
					jar.extractFilesFromJarFile(FileSecConstants.JAR_FILE, FileSecConstants.ALLFILES);
				}
				
				/***
				 *  CHECK THE COMMAND LINE FLAGS & Perform verification of:
				 *  	1. Digital Signature (Using public key from keystore)
				 *  	2. MAC (Using password provided by the user)
				 */
				if (argsmap.containsKey(FileSecConstants.signVerify))	verifySign();
				if (argsmap.containsKey(FileSecConstants.macVerify))	verifyMac();
				
				if (logtool != null) logtool.info("CLEANING UP RESIDUAL ENCRYPTED FILES ON RECEIVER SIDE");
				cleanupResidualFiles(jar.listJarContents(FileSecConstants.JAR_FILE));
		}
	}

	/***
	 * Convenience method used to remove residual encrypted files from local
	 * directory on both sender and receiver end, once the jar file has been
	 * successfully created or extracted respectively
	 * @param files
	 */
	private void cleanupResidualFiles(ArrayList<String> files) 
	{
		for (int i=0;i<files.size();i++)
			new File(files.get(i)+".CRYPT").delete();	// REMOVE ALL .CRYPT FILES AND JarConfig.xml
		new File("JarConfig.xml").delete();				// CLEAR ALL HASHMAPS AND EXIT GRACEFULLY
		
		argsmap.clear();		argsmap 	 = null;
		localparams.clear();	localparams  = null;
		jarinparams.clear();	jarinparams  = null;
		jaroutparams.clear();	jaroutparams = null;
		
		if (logtool != null) logtool.info("Cleared command line arguments 	 - argsmap	  ");
		if (logtool != null) logtool.info("Cleared LocalConfig.xml arguments - localparams ");
		if (logtool != null) logtool.info("Cleared JarConfig.xml arguments 	 - jarinparams ");
		if (logtool != null) logtool.info("Cleared LocalConfig.xml arguments - jaroutparams");
	}

	/***
	 * Generate random Initialization Vector based on IV size defined in LocalConfig.xml
	 * and write the IV into JarConfig.xml file. Return IV to calling function to be used
	 * for encryption of each file
	 * 
	 * @param ivSize
	 * @return
	 */
	private IvParameterSpec generateInitializationVector(int ivSize) 
	{
		final SecureRandom random = new SecureRandom();
		IvParameterSpec ivParam = null;
		if (ivSize > 0) 
		{
			byte[] iv = new byte[ivSize];
			random.nextBytes(iv);
			ivParam = new IvParameterSpec(iv);
			String finalIv = Base64.encodeBytes(iv);
			jaroutparams.put("IV", finalIv);
			if (logtool != null) logtool.info("Generated 8-bit IV for encryption");
		}
		return ivParam;
	}

	/**
	 * Define a new instance of the PKICryptoEngine and generate a new symmetric
	 * session key. Encrypt the session key with the public key of the sender and
	 * write encrypted session key to jaroutparams which will later be written to
	 * the generated JarConfig.xml file
	 * 
	 * @throws InvalidKeyException
	 * @throws Exception
	 */
	private void encryptPKI() throws FileSecException
	{
		PKICryptoEngine pkiInstance = new PKICryptoEngine();
		String SYM_KEY_TYPE= localparams.get("SymmetricKeyType");
		String pkiCipherType = localparams.get("AsymmetricCipher");
		int SYM_KEY_LENGTH= Integer.parseInt(localparams.get("SymmetricKeySize"));;
		SecretKey sessionkey= generateSessionkey(SYM_KEY_TYPE, SYM_KEY_LENGTH);
		if (logtool != null) logtool.info("Generated Symmetric Session key for file encryption");
		String stringkey = new String(sessionkey.getEncoded());
		String encryptedsessionkey= pkiInstance.encrypt((String)argsmap.get("-ec"), pkiCipherType, stringkey, 
									FileSecConstants.KEYSTORE,FileSecConstants.STOREPASS, FileSecConstants.KEYPASS);
		jaroutparams.put("EncryptedPKISessionKey", encryptedsessionkey);
		if (logtool != null) logtool.info("Encrypted the session key with PKI(Public key)");
		jaroutparams.put("PKISessionKey", sessionkey);
	}

	/***
	 * Define a new instance of the PBECryptoEngine and generate a new symmetric
	 * session key. Encrypt the session key with the pasword provided by user and
	 * write encrypted session key to jaroutparams which will later be written to
	 * the generated JarConfig.xml file
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
    private void encryptPBE() throws FileSecException  // #SSN
    {
        PBECryptoEngine pbeInstance = new PBECryptoEngine();
        String SYM_KEY_TYPE= localparams.get("SymmetricKeyType");
        String cipherType= localparams.get("PBECipher");
        int SYM_KEY_LENGTH= Integer.parseInt(localparams.get("SymmetricKeySize"));
        SecretKey sessionkey= generateSessionkey(SYM_KEY_TYPE, SYM_KEY_LENGTH);
        ArrayList<String> passarr= (ArrayList<String>)argsmap.get(FileSecConstants.ep);
        if (logtool != null) logtool.info("Hashing passwords from command line for encrypt option");
        for(int i=0;i<passarr.size();i++)
        {
            jaroutparams.put("Hashpassword"+i, pbeInstance.hashPassword(passarr.get(i)));
            String encryptedsessionkey = pbeInstance.encrypt(cipherType, passarr.get(i), new String(sessionkey.getEncoded()));
            jaroutparams.put("EncryptedPBESessionKey"+i, encryptedsessionkey);
        }
        if (logtool != null) logtool.info("Encrypted session key using passwords with PBE");
        jaroutparams.put("PBESessionKey", sessionkey);
    }

	
	/***
	 * On the receiver side, instantiate a PKICryptoEngine to read the encrypted
	 * session key and decrypt it with the private key of sender, found at alias
	 * in the receiver's keytore. Put the decrypted session key into jarinparams
	 * HashMap .... we'll use it further in decryption of files extracted from
	 * the jar file
	 * 
	 * @throws Exception
	 */
	private void decryptPKI() throws FileSecException
	{
		PKICryptoEngine pkiInstance = new PKICryptoEngine();
		String pkiCipherType = localparams.get("AsymmetricCipher");
		String encryptedsessionkey = (String)jarinparams.get("PKIKey");
		String SYM_KEY_TYPE= localparams.get("SymmetricCipher");
		String decryptedsessionkey=pkiInstance.decrypt((String)argsmap.get("-dc"), pkiCipherType, encryptedsessionkey, 
										FileSecConstants.KEYSTORE,FileSecConstants.STOREPASS, FileSecConstants.KEYPASS,
										SYM_KEY_TYPE);
        if (logtool != null) logtool.info("Decrypted session key from xml using (PKI) Privatekey");
        System.out.println("~~~~~~~~~~"+decryptedsessionkey);
		jarinparams.put("DecryptedPKISessionKey", decryptedsessionkey);
	}

	/***
	 * On the receiver side, instantiate a PBECryptoEngine to read the encrypted
	 * session key and decrypt it with the password on command line. Write out the
	 * decrypted session key into jarinparams HashMap .... we'll use it further in
	 * decryption of files extracted from the jar file
	 * 
	 * @throws Exception
	 */
	@SuppressWarnings({ "unused", "unchecked" })
    private void decryptPBE() throws FileSecException 
    {
        PBECryptoEngine pbeInstance = new PBECryptoEngine();
        String pbeCipherType= localparams.get("PBECipher");
        String encryptedsessionkey= "";
        ArrayList<String> hasharr= (ArrayList<String>)jarinparams.get("Hashes_of_passwords");
        ArrayList<String> sessionkey = (ArrayList<String>)jarinparams.get("Encrypted_keys");
        String tocheck= pbeInstance.hashPassword((String)argsmap.get(FileSecConstants.dp));

        for(int i=0;i<hasharr.size();i++)
        {
            if(tocheck.equals(hasharr.get(i)))
            {
            	encryptedsessionkey=sessionkey.get(i);
            	break;
            }        
        }
        if (logtool != null) logtool.info("Located the password corresponding to this encrypted session key");
        String decryptedsessionkey= pbeInstance.decrypt(pbeCipherType,(String)argsmap.get("-dp"),encryptedsessionkey);
        jarinparams.put("DecryptedPBESessionKey", decryptedsessionkey);
    }

	
	/***
	 * Generate MAC for the files listed on command line. Read all the files in
	 * order into a byte array, and feed this byte array to the MAC engine after
	 * initializing it properly. The result is a fixed-length MAC over all files
	 * contained in the jar file
	 * 
	 * @throws Exception
	 */
	private void macFiles() throws FileSecException
	{
		String algorithm = localparams.get("MACHashAlgorithm");
		JarMACEngine helper = new JarMACEngine();
		String mac = helper.GenerateMACForJar(FILE_LIST, algorithm, (String)argsmap.get("-mac"));
        if (logtool != null) logtool.info("Generated a single MAC over the byte[] contents of all files");
		jaroutparams.put("MAC", mac);
	}

	/***
	 * Generate a Digital Signature for the files listed on command line. Read all
	 * the files in order into a byte array, and feed this byte array into the sign
	 * engine after initializing it properly. The result is a digital signature over
	 * all files contained in the jar file. We then write this signature to JarConfig
	 * xml file which we add to the jar file
	 * 
	 * @throws Exception
	 */
	private void signFiles() throws FileSecException
	{
		jaroutparams.put("alias", (String)argsmap.get(FileSecConstants.sign));
		String signAlgorithm = localparams.get("SigningAlgorithm");
		JarSignEngine helper = new JarSignEngine(signAlgorithm);
		String signature = helper.GenerateSignForJAR(FILE_LIST, (String)argsmap.get(FileSecConstants.sign), 
							FileSecConstants.KEYSTORE, FileSecConstants.KEYPASS, FileSecConstants.STOREPASS);
        if (logtool != null) logtool.info("Generated a Digital Signature over the byte[] contents of all files listed");
		jaroutparams.put("Sign", signature);
	}
	
	/***
	 * At the receiver end, the MAC needs to be verified. By now, any encrypted
	 * files contained in the jar have been extracted and decrypted successfully
	 * already. Obtain a list of all these files, read the contents of all the
	 * files one by one into a byte array, and recompute the MAC. Return success
	 * if the regenerated MAC matches that obtained from the JarConfig.xml 
	 * 
	 * @throws Exception
	 */
	private void verifyMac() throws FileSecException
	{
		JarMACEngine helper= new JarMACEngine();
		JarUtil jar= new JarUtil();
		ArrayList<String> files=jar.listJarContents(FileSecConstants.JAR_FILE);
		if (logtool != null) logtool.info(" Read the contents of all jar content files into a byte[]");
		String hashFromXML=(String)jarinparams.get("Mac");
		if (logtool != null) logtool.info(" Read the hash from xml");
		String password=(String) argsmap.get(FileSecConstants.macVerify); 
		
		boolean bool=helper.verifyMACForJar(password, hashFromXML, localparams, files);
		if (bool==true)
			if (logtool != null) logtool.info("[TRACE]  HASHES MATCH - MAC Verified");
		else if (bool == false)
			if (logtool != null) logtool.info("[ERROR]  Hashes dont match - Jar file invalid");

	}

	/***
	 * At the receiver end, the sign needs to be verified. By now, any encrypted
	 * files contained in the jar have been extracted and decrypted successfully
	 * already. Obtain a list of all these files, read the contents of all the
	 * files one by one into a byte array, and verify the signature read from the
	 * Jarconfig.xml using the sender's public key. Return success if the verify
	 * engine returns true
	 * 
	 * @throws Exception
	 */
	private void verifySign() throws FileSecException
	{
		if (logtool != null) logtool.info("Looking up public key at alias "+(String)jarinparams.get("Alias"));
		String signAlgorithm = localparams.get("SigningAlgorithm");
		JarSignEngine helper = new JarSignEngine(signAlgorithm);
		JarUtil jar = new JarUtil();
		ArrayList<String> files = jar.listJarContents(FileSecConstants.JAR_FILE);
		Collections.sort(files);
		if (logtool != null) logtool.info("Retrieved sorted file list from jar");
		
		byte[] contents = jar.readFilesIntoBuffer(files);
		String signature = (String)jarinparams.get("Signature");
		String alias = (String)jarinparams.get("Alias");
		
		if (logtool != null) logtool.info("Verifying jar signature with alias at "+(String)jarinparams.get("Alias"));
		boolean status = helper.verifySignForJAR(contents, signature, alias, FileSecConstants.KEYSTORE, 
												FileSecConstants.KEYPASS, FileSecConstants.STOREPASS);
		if (status == true)
			logtool.info("[TRACE] Signatures match - SIGN Verified");
		else if (status == false)
			logtool.info("[ERROR] Signatures dont match - Jar file invalid");

	}

	/***
	 * On the receiver end, verify that the current time is not After the
	 * deadline specified when the sender created the jar. If the notAfter
	 * timeline has been crossed, return error message and exit
	 * @param date
	 * @return
	 * @throws ParseException
	 */
	private boolean verifyNotAfter(String date) throws FileSecException
	{
		DateValidator datecheck = new DateValidator();
        if (logtool != null) logtool.info("Verifying -notAfter flag");
		return (datecheck.isAfter(date));
	}
	
	/***
	 * On the receiver end, verify that the current time is not Before the
	 * time specified when the sender created the jar. If the notAfter time
	 * has been crossed, return error message and exit	 
	 * @param date
	 * @return
	 * @throws ParseException
	 */
	private boolean verifyNotBefore(String date) throws FileSecException
	{
		DateValidator datecheck = new DateValidator();
        if (logtool != null) logtool.info("Verifying notBefore flag");
		return (datecheck.isBefore(date));
	}
	
	/***
	 * GENERATES A SYMMETRIC SESSION KEY TO BE USED FOR ENCRYPTION/DECRYPTION
	 * OF FILES LISTED ON COMMAND LINE BEFORE ADDING THEM TO THE CONTAINER JAR
	 * 
	 * @param SYM_KEY_TYPE
	 * @param SYM_KEY_LENGTH
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	SecretKey generateSessionkey(String SYM_KEY_TYPE, int SYM_KEY_LENGTH) throws FileSecException
	{
		KeyGenerator kg= null;
		try 
		{
			kg= KeyGenerator.getInstance(SYM_KEY_TYPE);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0009, e);
		}
		kg.init(SYM_KEY_LENGTH);
		SecretKey key= kg.generateKey();
        if (logtool != null) logtool.info("Successfully generated a Symmetric Session Key");
		return key;
	}

}
