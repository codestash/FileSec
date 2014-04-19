
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

import java.util.logging.Logger;

public class FileSecException extends Exception 
{
	private static final long serialVersionUID = -783605768977112215L;
	private static Logger logtool = FileSecConstants.logging;

	public FileSecException(String m)
	{
		super(m);
		if (logtool != null) logtool.info("[ERROR]  "+m);
	}
	
	public FileSecException(Exception e)
	{
		super(e);
		if (logtool != null) logtool.info("[ERROR]  Exception thrown");
	}
	
	public FileSecException(String errmessage, Exception e)
	{
		super(errmessage,e);
		if (logtool != null) logtool.info("[ERROR]	Exception thrown - "+errmessage);
	}
	
	public FileSecException(String message, Exception e, Throwable t)
	{
		super(message, t);
	}
}

