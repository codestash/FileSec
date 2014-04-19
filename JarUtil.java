
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.io.File;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.jar.JarFile;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.logging.Logger;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class JarUtil
{
	private static Logger logtool = FileSecConstants.logging;
	
	/***
	 * Create a new jar file with name specified by argument jarFilePath and
	 * add these files as entries into the jar.
	 * @param jarFilePath
	 * @param files
	 * @throws FileSecException
	 */
	void createJarFile(String jarFilePath, ArrayList<String> files) throws FileSecException 
	{
		BufferedOutputStream bos;
		JarOutputStream jos;
		try 
		{
			bos = new BufferedOutputStream(new FileOutputStream(jarFilePath));
			jos = new JarOutputStream(bos);
			for (String f : files) {
				BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
				JarEntry je = new JarEntry(f);
				if (logtool != null) logtool.info("Adding :"+je.getName() + " to Jarfile");
				jos.putNextEntry(je);
				byte[] buf = new byte[FileSecConstants.BUFFER_SIZE];
				int count;
				while ((count = bis.read(buf)) != -1)
					jos.write(buf, 0, count);
				bis.close();
			}
			jos.close();
			bos.close();
		} 
		catch (FileNotFoundException e) 
		{
			System.out.println("FileNotFoundException encountered while creating jarfile");
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0062, e);
		}
		catch (IOException e) 
		{
			System.out.println("IOException encountered while creating jarfile");
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0063, e);
		}
	}

	/***
	 * Reads a jarfile path as specified by jarFilePath, reads each file listed
	 * into a new output stream, transforms the stream of data using TransformFile
	 * and writes the encrypted data to a new entry in jar file
	 * @param jarFilePath
	 * @param cipherType
	 * @param key
	 * @param iv
	 * @param files
	 * @throws FileSecException
	 */
	void createEncryptedJarFile(String jarFilePath, String cipherType, SecretKey key, 
								IvParameterSpec iv, ArrayList<String> files) throws FileSecException 
	{
		try
		{
			BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(jarFilePath));
			JarOutputStream jos = new JarOutputStream(bos);
	
			for (int i=0;i<files.size();i++) 
			{
				String f = files.get(i);
				JarEntry je = new JarEntry(f);
				if (logtool != null) logtool.info("Adding :"+je.getName() + " to Jarfile");
				if(!je.getName().equals(FileSecConstants.JARCONFIG))
				{
					if (logtool != null) logtool.info("Encrypting file");
					TransformFile(cipherType, Cipher.ENCRYPT_MODE, iv, key,
							je.getName(), je.getName()+".CRYPT");
					JarEntry encje = new JarEntry(je.getName()+".CRYPT");
					jos.putNextEntry(encje);
					BufferedInputStream encbis = new BufferedInputStream(new FileInputStream(f+".CRYPT"));
					byte[] buf = new byte[FileSecConstants.BUFFER_SIZE];
					int count;
					while ((count = encbis.read(buf)) != -1)
						jos.write(buf, 0, count);
					encbis.close();					
					if (logtool != null) logtool.info("Successfully added :"+je.getName());
				}
				else
				{
					if (logtool != null) logtool.info("Adding : JarConfig.xml to Jarfile");
					BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f));
					jos.putNextEntry(je);
					byte[] buf = new byte[FileSecConstants.BUFFER_SIZE];
					int count;
					while ((count = bis.read(buf)) != -1)
						jos.write(buf, 0, count);
					bis.close();
					if (logtool != null) logtool.info("Successfully added JarConfig.xml");
				}
			}
			jos.close();
			bos.close();
		}
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068+cipherType, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069+cipherType, e);
		}

	}

	/***
	 * Actual encryption function which "TRANSFORMS" input plaintext file into
	 * an encrypted file in ENCRYPT mode, and decrypts the ciphertext file to
	 * a plaintext file in DECRYPT mode. Writes out the resulting file to folder
	 * 
	 * @param cipherType
	 * @param mode
	 * @param ivParam
	 * @param key
	 * @param inFileName
	 * @param outFileName
	 * @throws FileSecException
	 */
	@SuppressWarnings("unused")
	public void TransformFile(String cipherType, int mode, IvParameterSpec ivParam, SecretKey key,
							  String inFileName, String outFileName) throws FileSecException 
	{
		try 
		{
			if (logtool != null) logtool.info("Cipher type is - "+cipherType);
			Cipher cipher = Cipher.getInstance(cipherType);
			cipher.init(mode, key, ivParam);
			FileInputStream fis = new FileInputStream(inFileName);
			FileOutputStream fos = new FileOutputStream(outFileName);
			InputStream is = (mode == Cipher.ENCRYPT_MODE) ?
					(new BufferedInputStream(fis)) : (new CipherInputStream(fis, cipher));
			OutputStream os = (mode == Cipher.ENCRYPT_MODE) ?
					(new CipherOutputStream(fos, cipher)) :	(new BufferedOutputStream(fos));
			if (logtool != null) logtool.info("Writing transformed data to output file");

			int data = 0;
			while ((data = is.read()) >= 0)
			{
				os.write(data);
			}
			is.close(); 
			os.close();
			
		} catch (NoSuchAlgorithmException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0064+cipherType, e);
		}
		catch (NoSuchPaddingException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0065+cipherType, e);
		}
		catch (InvalidKeyException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0066+cipherType, e);
		} 
		catch (InvalidAlgorithmParameterException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0067+cipherType, e);
		} 
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068+cipherType, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069+cipherType, e);
		}
		
	}

	/***
	 * Extract simple (unencrypted) files from the jar and place them into
	 * the current working folder.
	 * @param jarFilePath
	 * @param settings
	 * @throws FileSecException
	 */
	void extractFilesFromJarFile(String jarFilePath, String settings) throws FileSecException 
	{
		try
		{
			JarFile jf = new JarFile(jarFilePath);
			Enumeration<JarEntry> entries = jf.entries();
			while (entries.hasMoreElements()) 
			{
				JarEntry je = entries.nextElement();
				InputStream fin = jf.getInputStream(je);
				BufferedInputStream bis = new BufferedInputStream(fin);
				final String MANIFEST = "META-INF/";
	
				if (settings.equals(FileSecConstants.ALLFILES))
				{
					// write out file, as long as it isn't part of manifest subdirectory
					if (je.getName().length() < MANIFEST.length() ||
							!je.getName().substring(0,MANIFEST.length()).equals(MANIFEST)) 
					{
						if (logtool != null) logtool.info("Extracting from jar: "+je.getName());
						BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(je.getName()));
						byte[] buf = new byte[FileSecConstants.BUFFER_SIZE];
						int count;
						while ((count = bis.read(buf)) != -1)
							bos.write(buf, 0, count);
						bos.close();
						bis.close();
					}
				}
				else if (settings.equals(FileSecConstants.JARCONFIG))
				{
					if (je.getName().equals(FileSecConstants.JARCONFIG)) 
					{
						if (logtool != null) logtool.info("Extracting from jar: "+je.getName());
						BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(je.getName()));
						byte[] buf = new byte[FileSecConstants.BUFFER_SIZE];
						int count;
						while ((count = bis.read(buf)) != -1)
							bos.write(buf, 0, count);
						bos.close();
						bis.close();
					}
					if (logtool != null) logtool.info("Successfully extracted JarConfig.xml");
				}
			}
		}
		catch (IOException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069, e);
		}
	}

	/***
	 * Extract the encrypted contents of the jar file onto the local directory.
	 * Decrypt these files and write them to files of original names. Return if
	 * successful 
	 * 
	 * @param jarFilePath
	 * @param cipherType
	 * @param ivParam
	 * @param key
	 * @throws FileSecException
	 */
	void decryptJarContents(String jarFilePath, String cipherType, IvParameterSpec ivParam, SecretKey key)
																				   throws FileSecException 
	{
		try
		{
			JarFile jf = new JarFile(jarFilePath);
			Enumeration<JarEntry> entries = jf.entries();
			while (entries.hasMoreElements()) 
			{
				JarEntry je = entries.nextElement();
				if (je.getName().equals(FileSecConstants.JARCONFIG))
					continue;
				// STRIP OFF THE .CRYPT EXTENSION TO RECOVER ORIGINAL FILENAME
				String decryptFilename = je.getName().substring(0, je.getName().indexOf(".CRYPT"));
				if (logtool != null) logtool.info("Extracting from jar: "+je.getName());
				if (logtool != null) logtool.info("DECRYPTING FILE");
				TransformFile(cipherType, Cipher.DECRYPT_MODE, ivParam, key, je.getName(), decryptFilename);
			}
		}
		catch (IOException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069, e);
		}
	}

	/***
	 * Convenience method to read entire contents of a JAR file (Encrypted/ Unencrypted)
	 * into a byte[] buffer which can then be used to VerifySign, generateSign etc. for
	 * authentication purposes
	 * 
	 * @param jarFilePath
	 * @return
	 * @throws FileSecException
	 */
	public byte[] readJarFileIntoBuffer(String jarFilePath) throws FileSecException
	{
			Hashtable<String, byte[]> FileMap = new Hashtable<String, byte[]>() ;
			String content = "";
		try
		{
			FileInputStream fis=new FileInputStream(jarFilePath);
			BufferedInputStream bis=new BufferedInputStream(fis);
			JarInputStream zis=new JarInputStream(bis);
			JarEntry ze=null;
			while ((ze=zis.getNextJarEntry())!=null) 
			{
				if (logtool != null) logtool.info("Reading into byte[] : "+ze.getName());
				if (ze.isDirectory() || ze.getName().contains("META-INF/") || ze.getName().equals(FileSecConstants.JARCONFIG))
					continue;
				if (logtool != null) logtool.info("ze.getName()="+ze.getName()+","+"getSize()="+ze.getSize());
				int size = bis.available();
	
				byte[] buf=new byte[size];
				int rb=0, chunk=0;
				while ((size - rb) > 0) 
				{
					chunk=zis.read(buf,rb,(int)size - rb);
					if (chunk==-1)
						break;
					rb+=chunk;
				}
				FileMap.put(ze.getName(), buf);
				// READ ENTIRE byte[] INTO A STRING AND APPEND TO PREVIOUSLY READ BYTES
				String filebuf = new String(buf);
				content+=filebuf;
			}
		}
		catch (IOException e)
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069, e);
		}
		return content.getBytes();
	}

	/***
	 * Convenience method which reads a list of files into a byte[] buffer and
	 * returns its contents to calling function for further operations
	 * 
	 * @param filenames
	 * @return
	 * @throws FileSecException
	 */
	public byte[] readFilesIntoBuffer(ArrayList<String> filenames) throws FileSecException
	{
		String content = "";
		Collections.sort(filenames);
		try
		{
			for(int i=0;i<filenames.size();i++)
			{
				File name = new File(filenames.get(i));
				if (logtool != null) logtool.info("Reading file : "+name+" into byte[] buffer");
				if (name.isDirectory() || name.getName().contains("META-INF/") || name.getName().equals(FileSecConstants.JARCONFIG))
					continue;
	
				FileInputStream fis=new FileInputStream(name);
				BufferedInputStream bis=new BufferedInputStream(fis);
				int size = bis.available();
	
				byte[] buf=new byte[size];
				int rb=0, chunk=0;
				while ((size - rb) > 0) 
				{
					chunk=bis.read(buf,rb,(int)size - rb);
					if (chunk==-1)
						break;
					rb+=chunk;
				}
				// APPEND byte[] FROM THIS FILE TO A STRING CONTAINING PREVIOUSLY READ BYTES
				String filebuf = new String(buf);
				content+=filebuf;
			}
		}
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069, e);
		}
		return content.getBytes();
	}
	
	/***
	 * LISTS OUT NAMES OF ALL FILES IN THE JAR FILE SPECIFIED BY jarname 
	 * (Excluding  JarConfig.xml) and returns this list to calling method
	 * @param jarname
	 * @return
	 * @throws FileSecException
	 */
	public ArrayList<String> listJarContents(String jarname) throws FileSecException
	{
		ArrayList<String> files = new ArrayList<String>();
		try
		{
			FileInputStream fis=new FileInputStream(jarname);
			BufferedInputStream bis=new BufferedInputStream(fis);
			JarInputStream zis=new JarInputStream(bis);
			JarEntry ze=null;
			while ((ze=zis.getNextJarEntry())!=null) 
			{
				if (ze.getName().equals(FileSecConstants.JARCONFIG))
					continue;
				else if (ze.getName().contains(".CRYPT"))
					files.add(ze.getName().substring(0, ze.getName().indexOf(".CRYPT")));
				else
					files.add(ze.getName());
				
				if (logtool != null) logtool.info("File : "+ze.getName());
			}
			Collections.sort(files);
		}
		catch (FileNotFoundException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0068, e);
		} 
		catch (IOException e) 
		{
			throw new FileSecException(ErrorCodes.ERR_FILESEC_0069, e);
		}
		return files;
	}
}

