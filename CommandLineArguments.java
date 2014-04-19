
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.logging.Logger;

public class CommandLineArguments 
{
	public HashMap<String, Object> parsing(String[] args) throws FileSecException
	{
		Logger logtool = null;
		HashMap<String, Object> argsmap = new HashMap<String, Object>(); // HASHMAP TO HOLD ALL COMMAND LINE ARGUMENTS
		int pos=0;

		/***
		 * CHECK IF DEBUG MODE IS CALLED FROM COMMAND LINE. IF YES, DEFINE
		 * A LOGGER IN INFO MODE TO CAPTURE DEBUG EXECUTION INFORMATION
		 */
		for( int i=0;i<args.length;i++)
		{
			if (args[i].equals("-debug"))
			{
				FileSecConstants.setDebug = true;
				logtool = Logger.getLogger(FileSec.class.getName());	 	 // INITIALIZING DEFAULT LOGGER
				FileSecConstants.logging = logtool;
				logtool.info("[TRACE]  Debug level enabled -- FileSec will run in FINEST logging mode");
				break;
			}
		}

		/***
		 * 	We now iterate through the entire list of arguments passed as String[]
		 *  from command line and associate each tag with the value specified thru
		 *  user input. If any error occurs, FileSecException with appropriate msg
		 *  is thrown. After all arguments have been read, the resulting HashMap is
		 *  returned to FileSec main class which then processes the commands 
		 *  
		 */
		while(pos < args.length)
		{
			if(args[pos].equals(FileSecConstants.sign))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.sign,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Sign with alias - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -sign but no alias was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.sign);
				}
			}
			
			else if(args[pos].equals(FileSecConstants.signVerify))
			{
				argsmap.put(FileSecConstants.signVerify,true);
				if (logtool != null)   logtool.info("[TRACE]  Verify Digital Signature for this jar file");
				pos++;
			}
			
			else if(args[pos].equals(FileSecConstants.mac))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.mac,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Generate MAC with password - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -mac but no password was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.mac);
				}
			}

			else if(args[pos].equals(FileSecConstants.macVerify))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.macVerify, args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Verify MAC with password - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -macVerify but no password was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.macVerify);
				}
			}
			
			else if(args[pos].equals(FileSecConstants.ep))
			{
				pos++;
				ArrayList<String> passarr = new ArrayList<String>();
				while(!args[pos].startsWith("-"))
				{
					passarr.add(args[pos]);
					System.out.println("IN HERE");
					pos++;
				}
				if (passarr.size() == 0)
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -ec but no passwords was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.ep);
				}
				argsmap.put(FileSecConstants.ep, passarr);
			}

			else if(args[pos].equals(FileSecConstants.ec))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.ec,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Encrypt JAR file content with Public key at alias - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -ec but no alias was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.ec);
				}
			}

			else if(args[pos].equals(FileSecConstants.dp))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.dp,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Decrypt encrypted jar with password - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -dp but no password was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.dp);
				}
			}

			else if(args[pos].equals(FileSecConstants.dc))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.dc,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Decrypt JAR with private key at alias - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -dc but no alias was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.dc);
				}
			}

			else if(args[pos].equals(FileSecConstants.jar))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.jar, args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Jar name to be created/verified is - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -jar but no jarname was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.jar);
				}
			}
			
			else if(args[pos].equals(FileSecConstants.config))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.config, args[pos]);
					if (logtool != null)   logtool.info("[TRACE] Use config parameters from - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -config but no XML config file was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.config);
				}
			}
			
			else if(args[pos].equals(FileSecConstants.keystore))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.keystore, args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Keystore file - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -keystore but no keystore was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.keystore);
				}
			}

			else if(args[pos].equals(FileSecConstants.storepass))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.storepass,args[pos]);
					if (logtool != null)   logtool.info("[TRACE] Keystore password - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -storepass but no store password was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.storepass);
				}
			}

			else if(args[pos].equals(FileSecConstants.keypass))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.keypass, args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  Entry password - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -keypass but no entry password was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.keypass);
				}
			}

			else if(args[pos].equals(FileSecConstants.debug))
			{
				FileSecConstants.setDebug= true;
				argsmap.put(FileSecConstants.debug,FileSecConstants.setDebug);
				pos++;
			}

			else if(args[pos].equals(FileSecConstants.notAfter))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.notAfter, args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  JAR cannot be extracted after - "+args[pos]);
					pos++;
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -notAfter but no time was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.notAfter);
				}
			}

			else if(args[pos].equals(FileSecConstants.notBefore))
			{
				pos++;
				if(!args[pos].startsWith("-"))
				{
					argsmap.put(FileSecConstants.notBefore,args[pos]);
					if (logtool != null)   logtool.info("[TRACE]  JAR cannot be extracted before - "+args[pos]);
					pos++;	
				}
				else
				{
					if (logtool != null)   logtool.info("[TRACE]  Found argument -notBefore but no time was specified");
					throw new FileSecException("MISSING ARGUMENT FOR TAG - "+FileSecConstants.notBefore);
				}
			}
			else
				break;
		}
		
		ArrayList<String> arrlist = new ArrayList<String>();
		for(pos=pos++;pos<args.length;pos++)
		{
			String f= args[pos];
		
			/**
			 * Verify that filename is not invalid in any way i.e. it should not be a
			 * URL or directory path or FTP location etc. This way we can validate the
			 * filenames specified
			 */
			if	((f.contains("\\")) || (f.contains("/")) || (f.contains(":")) ||
			     (f.contains("<")) || (f.contains(">")) || (f.contains("http")) 
			     ||(f.contains("file://")) || (f.contains("ftp")))
			{
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0003);
			}
			else if ((!new File(f).exists())|| (!new File(f).canRead()))
			{
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0004);
			}
			else
			{
				arrlist.add(args[pos]);
			}
		}

		/***
		 *  If either encryption or signing operations are specified and no filenames
		 *  listed on command line, throw a new FileSecException with suitable error
		 *  message
		 */
		if (arrlist.size() == 0 && (argsmap.containsKey(FileSecConstants.ec) || argsmap.containsKey(FileSecConstants.ep)))
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0025);
		if (arrlist.size() == 0 && (argsmap.containsKey(FileSecConstants.mac) || argsmap.containsKey(FileSecConstants.sign)))
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0026);
	
		
		arrlist.add(FileSecConstants.JARCONFIG);
		Collections.sort(arrlist);
		// ADD ALL COMMAND LINE ARGUMENTS TO THIS HASHMAP AND RETURN
		argsmap.put(FileSecConstants.files, arrlist);
		return argsmap;
	}
} 
