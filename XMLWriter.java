
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

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class XMLWriter 
{

	/***
	 * CONVENIENCE METHOD TO WRITE PARAMETERS TO OUTPUT FILE
	 * JarConfig.xml WHICH WILL BE ADDED TO CREATED JAR FILE
	 * @param map
	 * @throws FileSecException
	 */
	public void writeJarConfigFile(HashMap<String, Object> map) throws FileSecException
	{
		try 
		{
			FileWriter xml = new FileWriter("JarConfig.xml");
			xml.write("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>			\n");
			xml.write("<JarConfig>												\n");
			xml.write("\t\t<CryptoAlgorithms>									\n");
			xml.write("\t\t\t<CryptoAlgorithm>DES</CryptoAlgorithm>				\n");
			xml.write("\t\t\t<CryptoAlgorithm>DESede</CryptoAlgorithm>			\n");
			xml.write("\t\t\t<CryptoAlgorithm>Blowfish</CryptoAlgorithm>		\n");
			xml.write("\t\t\t<CryptoAlgorithm>RSA</CryptoAlgorithm>				\n");
			xml.write("\t\t\t<CryptoAlgorithm>AES</CryptoAlgorithm>				\n");
			xml.write("\t\t\t<CryptoAlgorithm>DSA</CryptoAlgorithm>				\n");
			xml.write("\t\t</CryptoAlgorithms>									\n");
			xml.write("\t\t<MacAlgorithms>										\n");
			xml.write("\t\t\t<MacAlgorithm>SHA1</MacAlgorithm>					\n");
			xml.write("\t\t\t<MacAlgorithm>MD5</MacAlgorithm>					\n");
			xml.write("\t\t</MacAlgorithms>										\n");
			xml.write("\t\t<Timestamps>											\n");
			xml.write("\t\t\t<CreationTime>"+map.get("CreationTime")+"</CreationTime>\n");
			
			
			if(map.containsKey("NotBefore"))	
			{
				// NOT BEFORE TIMESTAMP
				xml.write("\t\t\t<NotBefore>"+map.get("NotBefore")+"</NotBefore>\n");
			}
			if(map.containsKey("NotAfter"))		
			{
				// NOT AFTER TIMESTAMP
				xml.write("\t\t\t<NotAfter>"+map.get("NotAfter")+"</NotAfter>\n");
			}
			
			xml.write("\t\t</Timestamps>											\n");
				// INITIALIZATION VECTOR
			xml.write("\t\t<Iv>"+map.get("IV")+"</Iv>								\n");
			
			if(map.containsKey("EncryptedPBESessionKey0"))
	        {
	            int i=0;
	            xml.write("\t\t<PBEEncryption>                                      \n");
	            while(map.containsKey("EncryptedPBESessionKey"+i))
	            {
	            	// WRITE ALL PASSWORD HASHES AND ENCRYPTED SESSION KEYS 
	            	// CORRESPONDING TO PASSWORD LIST PASSED ON COMMAND LINE
	                xml.write("\t\t\t<Hash"+i+">"+map.get("Hashpassword"+i)+
	                		"</Hash"+i+">\n");
	                xml.write("\t\t\t<Key"+i+">"+map.get("EncryptedPBESessionKey"
	                		+i)+"</Key"+i+">\n");
	                i++;
	            }
	            xml.write("\t\t<PasswordCount>"+i+"</PasswordCount>					\n");
	            xml.write("\t\t</PBEEncryption>                                     \n");
	        }
	
			if(map.containsKey("EncryptedPKISessionKey"))
			{
				xml.write("\t\t<PKIEncryption>										\n");
				// WRITE PKI ENCRYPTED SESSION KEY
				xml.write("\t\t\t<Key>"+map.get("EncryptedPKISessionKey")+"</Key>	\n");
				xml.write("\t\t</PKIEncryption>										\n");
			}
			if(map.containsKey("MAC"))	   
				xml.write("\t\t<MAC>"+map.get("MAC")+"</MAC>		\n");		// WRITE MAC
			if(map.containsKey("Sign"))   
				xml.write("\t\t<Sign>"+map.get("Sign")+"</Sign>		\n");		// WRITE SIGNATURE
			if(map.containsKey("alias"))   
				xml.write("\t\t<Alias>"+map.get("alias")+"</Alias>	\n");		// WRITE ALIAS
			
			xml.write("</JarConfig>\n");
			xml.close();
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0013,e);
		}
	}
	
	/***
	 * CONVENIENCE METHOD TO PARSE LOCAL CONFIG FILE - CALLED ON BOTH SENDER
	 * AND RECEIVER END. PUT ALL VALUES READ INTO A HASHMAP CALLED localparams
	 * @param configXMLFile
	 * @param localparams
	 * @throws FileSecException
	 */
	protected void readLocalConfigXML(String configXMLFile,HashMap<String, String> localparams)	throws FileSecException 
	{
		
		XMLParser xml = new XMLParser(configXMLFile);
		localparams.put("SymmetricCipher"	, 	xml.getElement("Symmetric.Cipher"));
		localparams.put("SymmetricKeyType"	, 	xml.getElement("Symmetric.KeyType"));
		localparams.put("SymmetricKeySize"	, 	xml.getElement("Symmetric.KeySize"));
		localparams.put("SymmetricIVSize"	, 	xml.getElement("Symmetric.IvSize"));
		localparams.put("AsymmetricCipher"	, 	xml.getElement("Asymmetric.Cipher"));
		localparams.put("AsymmetricSign"	,	xml.getElement("Asymmetric.Sign"));
		localparams.put("PBECipher"			,	xml.getElement("PBE.Cipher"));
		localparams.put("PBEKeyType"		,	xml.getElement("PBE.KeyType"));
		localparams.put("MACHashAlgorithm"	, 	xml.getTagByName("MACHashAlgorithm"));
		localparams.put("SigningAlgorithm"	, 	xml.getTagByName("SigningAlgorithm"));
		localparams.put("KeystorePath"		, 	xml.getTagByName("KeyStorePath"));
	}
	
	/***
	 * CONVENIENCE METHOD TO PARSE JAR CONFIG FILE - CALLED ON RECEIVER END.
	 * PUT ALL VALUES READ INTO A HASHMAP CALLED jarinparams AND RETURN
	 * @param jarconfigXML
	 * @param jarinparams
	 * @throws FileSecException
	 */
	protected void readJarConfigXML(String jarconfigXML, HashMap<String, Object> jarinparams) throws FileSecException 
    {
        XMLParser xml = new XMLParser(jarconfigXML);
        String[] cryptalgs = xml.getAllTagsByName("CryptoAlgorithm");
        String[] macalgs = xml.getAllTagsByName("MacAlgorithm");

        
        if (!(cryptalgs.length == 0 || cryptalgs == null))      jarinparams.put("CryptoAlgorithms"  , cryptalgs);
        if (!(macalgs.length == 0 || macalgs == null))          jarinparams.put("MacAlgorithms"     , macalgs);
        if (!(xml.getTagByName("NotBefore") == null))           jarinparams.put("BeforeTime"    	, xml.getTagByName("NotBefore"));
        if (!(xml.getTagByName("NotAfter") == null))            jarinparams.put("AfterTime"        	, xml.getTagByName("NotAfter"));
        if (!(xml.getTagByName("Sign") == null))                jarinparams.put("Signature"        	, xml.getTagByName("Sign"));
        if (!(xml.getTagByName("Alias") == null))               jarinparams.put("Alias"            	, xml.getTagByName("Alias"));
        if (!(xml.getTagByName("MAC") == null))                 jarinparams.put("Mac"            	, xml.getTagByName("MAC"));
        if (!(xml.getTagByName("Iv") == null))                  jarinparams.put("IV"            	, xml.getTagByName("Iv"));
        if (!xml.getElement("PKIEncryption.Key").equals(""))    jarinparams.put("PKIKey"        	, xml.getElement("PKIEncryption.Key"));
        
        if (!(xml.getElement("PBEEncryption.Key0").equals("")))
        {
	        int i=0;
	        ArrayList<String> keys= new ArrayList<String>();
	        ArrayList<String> hashes= new ArrayList<String>();
	        
	        int passcount = Integer.parseInt(xml.getElement("PBEEncryption.PasswordCount"));
	        for(i=0;i<passcount;i++)
	        {
	            keys.add(xml.getElement("PBEEncryption.Key"+i));
	            hashes.add(xml.getElement("PBEEncryption.Hash"+i));
	        }
	
	        jarinparams.put("Encrypted_keys",keys );
	        jarinparams.put("Hashes_of_passwords",hashes);

        }
    }

}
