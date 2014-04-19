
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

import java.util.HashMap;

public class FileSec 
{
	/**
	 *  FILESEC - Main class that uses related classes and user specified options
	 *  to produce a protected container jar file
	 *  
	 * @param args
	 * @throws Exception 
	 * @throws Exception 
	 */
	public static void main(String[] args) throws FileSecException 
	{	
		if (args.length == 0)
		{
			// NO ARGUMENTS PASSED TO FileSec FROM COMMAND LINE
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0001);
		}
		CommandLineArguments cmd = new CommandLineArguments();
		HashMap<String, Object> argsmap = cmd.parsing(args);
		if(argsmap == null)
		{
			// PARSING UNSUCCESSFUL .. EXIT PROGRAM GRACEFULLY
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0002);
		}
		else
		{
			ExecutionHandler proc = new ExecutionHandler(argsmap);
			proc.executeCommand();
		}

	}

}
