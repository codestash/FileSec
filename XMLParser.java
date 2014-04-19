
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
import java.io.IOException;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class XMLParser 
{

	private Element root = null;
	private static Logger logtool = FileSecConstants.logging;
	
	/***
	 * User-defined constructor for XMLParser with XML name passed to it
	 * and setup a DocumentBuilder to parse contents of the XML
	 * @param xmlName
	 * @throws FileSecException
	 */
	public XMLParser(String xmlName) throws FileSecException
	{
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		Document doc;
		try 
		{
			docBuilderFactory.setIgnoringElementContentWhitespace(true);
			DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
			File sourceFile = new File(xmlName);
			doc = docBuilder.parse(sourceFile);
			if (logtool != null) logtool.info("Successfully set up XML Parser document");
		}
		catch (ParserConfigurationException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0024,e);
		}
		catch (SAXException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0023,e);
		}
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0013,e);
		}
		Element root = doc.getDocumentElement();
		this.root = root;
	}
	
	/***
	 * Find the element in XML corresponding to given tagname specified
	 * and return the value stored in that tag
	 * @param tagname
	 * @return
	 */
	public String getTagByName(String tagname)
	{
		NodeList list = root.getElementsByTagName(tagname);
		if (list.getLength() == 0)
			return null;
		String[] tagValues = new String[list.getLength()];
		for (int i=0;i<list.getLength();i++)
		{
			tagValues[i] = list.item(i).getTextContent();
			if (logtool != null) logtool.info("Retrieved from XML : "+tagname+" Value : "+tagValues[i]);
		}
		return tagValues[0];
	}
	
	/***
	 * If multiple tags containing same name exist, return a String[]
	 * array containing all their values back to ExecutionHandler
	 * @param tagname
	 * @return
	 */
	public String[] getAllTagsByName(String tagname)
	{
		NodeList list = root.getElementsByTagName(tagname);
		if (list.getLength() == 0)
			return null;
		String[] tagValues = new String[list.getLength()];
		for (int i=0;i<list.getLength();i++)
		{
			tagValues[i] = list.item(i).getTextContent();
			if (logtool != null) logtool.info("Retrieved from XML : "+tagname+" Value : "+tagValues[i]);
		}
		return tagValues;
	}
	
	/***
	 * Parse the XML and return attribute associated with tag defined by
	 * parameter "parent". Return the value enclosed by tags
	 * @param parent
	 * @return
	 */
	public String getElement(String parent)
	{
        NodeList listOfPersons = root.getElementsByTagName(parent.substring(0,parent.indexOf(".")));
        String val = "";
        for(int s=0; s<listOfPersons.getLength() ; s++)
        {
            Node firstPersonNode = listOfPersons.item(s);
            if(firstPersonNode.getNodeType() == Node.ELEMENT_NODE)
            {
            	Element firstPersonElement = (Element)firstPersonNode;
                NodeList firstNameList = firstPersonElement.getElementsByTagName(parent.substring(parent.indexOf(".")+1, parent.length()));
                Element firstNameElement = (Element)firstNameList.item(0);

                NodeList textFNList = firstNameElement.getChildNodes();
                val = textFNList.item(0).getNodeValue().trim();
    			if (logtool != null) logtool.info("Retrieved from XML : "+parent+" Value : "+val);

            }
        }
        return val;
	}
}
