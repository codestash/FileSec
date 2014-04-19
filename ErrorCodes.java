
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

	/***
	 * 		ErrorCodes defined for FileSec thrown by respective FileSecExceptions
	 * 		from within different locations in code	
	 */
public class ErrorCodes {

	public static final String ERR_FILESEC_0001 = "No arguments passed on command line";
	
	public static final String ERR_FILESEC_0002 = "Hashmap returned null - Error with parsing";
	
	public static final String ERR_FILESEC_0003 = "File format is invalid";
	
	public static final String ERR_FILESEC_0004 = "Invalid Filename - FILE DOES NOT EXIST";
	
	public static final String ERR_FILESEC_0005 = "Message Authentication failed";
	
	public static final String ERR_FILESEC_0006 = "Verification of MAC failed";
	
	public static final String ERR_FILESEC_0007 = "Decryption of Jar failed";
	
	public static final String ERR_FILESEC_0008 = "Encryption Algorithm is currently not supported";
	
	public static final String ERR_FILESEC_0009 = "Algorithm not available in the environment"; // NoSuchAlgorithm ex
	
	public static final String ERR_FILESEC_0010 = "Key can not be recovered";  // Unrecoverablekey ex
	
	public static final String ERR_FILESEC_0011 = "Key Store exception"; //KeyStore ex
	
	public static final String ERR_FILESEC_0012 = "One of a variety of certificate problems"; // Certificate ex
	
	public static final String ERR_FILESEC_0013 = "Failed or Interrupted I/O operations"; //IOException
	
	public static final String ERR_FILESEC_0014 = "Attempt to open a file specified by path name failed"; // FileNotFoundException
	
	public static final String ERR_FILESEC_0015 = "length of data provided to a block cipher is incorrect"; //IllegalBlockSizeException
	
	public static final String ERR_FILESEC_0016 = "data is not padded properly"; //BadPaddingException
	
	public static final String ERR_FILESEC_0017 = "Invalid keys"; //InvalidKeyException
	
	public static final String ERR_FILESEC_0018 = "Padding mechanism not available in the environment"; //NoSuchPaddingException
	
	public static final String ERR_FILESEC_0019 = "No such algorithm exception caught by JarSignEngine";
	
	public static final String ERR_FILESEC_0020 = "Invalid algorithm parameters exception";
	
	public static final String ERR_FILESEC_0021 = "Invalid key spec encountered - Key spec could be corrupted";
	
	public static final String ERR_FILESEC_0022 = "Unsupported encoding format detected";
	
	public static final String ERR_FILESEC_0023 = "SAX parser exception encountered while reading XML";
	
	public static final String ERR_FILESEC_0024 = "Parser configuration error encountered in XML reading";
	
	public static final String ERR_FILESEC_0025 = "Missing filename(s) for encryption";
	
	public static final String ERR_FILESEC_0026 = "Missing filename(s) for signing";
	
	public static final String ERR_FILESEC_0027 = "Exception while reading from keystore";
	
	public static final String ERR_FILESEC_0028 = "Certificate exception encountered";
	
	public static final String ERR_FILESEC_0029 = "Unrecoverable key exception while reading keystore";
	
	public static final String ERR_FILESEC_0030 = "Invalid key found in keystore";
	
	public static final String ERR_FILESEC_0031 = "Signature exception while parsing digitla signature";
	
	public static final String ERR_FILESEC_0061 = "Error parsing timestamp - Format should be yyyy.mm.dd-HH:SS ";
	
	public static final String ERR_FILESEC_0062 = "Jar file name provided points to an invalid location ";
	
	public static final String ERR_FILESEC_0063 = "I/O Error with opening output stream on jarname ";
	
	public static final String ERR_FILESEC_0064 = "Encryption algorithm undefined ";
	
	public static final String ERR_FILESEC_0065 = "Padding technique undefined for encryption ";
	
	public static final String ERR_FILESEC_0066 = "Invalid key provided to cryptoEngine";
	
	public static final String ERR_FILESEC_0067 = "One or more algorithm parameters could be missing/corupted";
	
	public static final String ERR_FILESEC_0068 = "File not found in specified location";
	
	public static final String ERR_FILESEC_0069 = "I/O Error with opening input stream on file";
	
	public static final String ERR_FILESEC_0070 = "One or more key parameters could be invalid/missing";
	
	public static final String ERR_FILESEC_0071 = "";
	
	public static final String ERR_FILESEC_0072 = "";
	
	public static final String ERR_FILESEC_0073 = "";
	
	public static final String ERR_FILESEC_0074 = "";
	
	public static final String ERR_FILESEC_0075 = "";
	
	public static final String ERR_FILESEC_0076 = "";
	
	public static final String ERR_FILESEC_0077 = "";
	
	public static final String ERR_FILESEC_0078 = "";
	
	public static final String ERR_FILESEC_0079 = "";
	
	public static final String ERR_FILESEC_0080 = "";
}
