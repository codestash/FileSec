
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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Logger;


public class DateValidator 
{
	
	Logger logtool = FileSecConstants.logging;
	
		/***
		 * Verify if date specified at Jar creation time has been crossed. If time
		 * has been exceeded, jarfile is now expired and can no longer be accessed
		 * Return to the user if notAfter timestamp has not been crossed, else show
		 * this error message and exit
		 * @param afterTime
		 * @return
		 * @throws FileSecException
		 */
		public boolean isAfter(String afterTime) throws FileSecException
		{
	        SimpleDateFormat fm = new SimpleDateFormat(FileSecConstants.dateformat);
	        Calendar c1 = Calendar.getInstance();
	        Calendar c2 = Calendar.getInstance();
	        Date afterDate;
			try 
			{
				afterDate = fm.parse(afterTime);	// PARSE DATE STRING USING FORMATTER YYYY.MM.DD-HH:SS
			} 
			catch (ParseException e) 
			{
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0061+ afterTime, e);
			}
	        c2.setTime(afterDate);
	        
	        if (logtool != null) logtool.info("CURRENT TIME 	- "+fm.format(c1.getTime()));
	        if (logtool != null) logtool.info("CONFIGURED TIME	- "+fm.format(c2.getTime()));
	       
	        if(c1.after(c2))
	        {
	        	if (logtool != null) 
	        		logtool.info("JAR has crossed its validity period and is no longer accessible");
				Runtime.getRuntime().exit(1);
	        }
	        return true;	        	
		}
		
		/***
		 * Verify if date specified at Jar creation time has been reached . If time has
		 * not been reached, jarfile exists but cannot be accessed until the configured
		 * time. Return to the user if notBefore timestamp has not been reached, else 
		 * show this error message and exit
		 * @param beforeTime
		 * @return
		 * @throws FileSecException
		 */
		public boolean isBefore(String beforeTime) throws FileSecException
		{
	        SimpleDateFormat fm = new SimpleDateFormat(FileSecConstants.dateformat);
	        Calendar c1 = Calendar.getInstance();
	        Calendar c2 = Calendar.getInstance();
	        Date beforeDate;
			try 
			{
				beforeDate = fm.parse(beforeTime);	// PARSE DATE STRING USING FORMATTER YYYY.MM.DD-HH:SS
			} 
			catch (ParseException e) 
			{
				throw new FileSecException(ErrorCodes.ERR_FILESEC_0061 + beforeTime, e);
			}
	        c2.setTime(beforeDate);
	        
	        if (logtool != null) logtool.info("CURRENT TIME 	- "+fm.format(c1.getTime()));
	        if (logtool != null) logtool.info("CONFIGURED TIME	- "+fm.format(c2.getTime()));
	       
	        if(c1.before(c2))
	        {
	        	if (logtool != null) 
	        		logtool.info("Jar contents cannot be extracted until "+beforeTime);
				Runtime.getRuntime().exit(1);
	        }
	        return true;
		}
}
