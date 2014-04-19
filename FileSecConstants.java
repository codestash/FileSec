package fileSec;

import java.util.logging.Logger;

/***
 * 	FileSecConstants class defines  all default  parameters and  command line tags
 *  recognized by the FileSec application. If values are not passed on the command
 *  line, FileSec automatically reverts to these default values
 *
 */
public class FileSecConstants 
{
	
			public 	static final String sign		= 	"-sign";
			public 	static final String mac			= 	"-mac";
			public 	static final String ep			= 	"-ep";
			public 	static final String dp			= 	"-dp";
			public 	static final String ec			= 	"-ec";
			public 	static final String dc			= 	"-dc";
			public 	static final String jar			= 	"-jar";
			public 	static final String signVerify	= 	"-signVerify";
			public 	static final String macVerify	=	"-macVerify";
			public 	static final String debug		= 	"-debug";
			public 	static final String notAfter	= 	"-notAfter";
			public 	static final String notBefore	= 	"-notBefore";
			public 	static final String config		= 	"-config";
			public 	static final String storepass	= 	"-storepass";
			public 	static final String keypass		= 	"-keypass";
			public 	static final String keystore	= 	"-keystore";
			public 	static final int BUFFER_SIZE 	= 	1024;
			public  static final String STORETYPE	= 	"JKS";
			public  static final String dateformat	=	"yyyy.MM.dd-HH:mm";
			
			public  static String files 			=	"-files";
			public  static boolean setDebug 		= 	false;					
			public  static String JAR_FILE 			= 	"FileSec.jar";
			public  static String LOCALCONFIG 		= 	"LocalConfig.xml";
			public  static String JARCONFIG 		= 	"JarConfig.xml";
			public  static String KEYSTORE 			= 	"keystore";
			public  static String STOREPASS			= 	"FileSec@123";
			public  static String KEYPASS		 	= 	"FileSec@123";
			public  static String BEFORE		 	= 	"2007.12.31-00:00";
			public  static String AFTER		 		= 	"2010.12.31-00:00";
			public  static String ALLFILES			= 	"all";
			public  static Logger logging			=   null;
			public  static String hashAlgo			=	"SHA-256";
			public  static String ENCODING			=	"UTF-8";
			public  static int macKeyLength			=	128;
}
