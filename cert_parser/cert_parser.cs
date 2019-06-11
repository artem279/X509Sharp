/*
 * Создано в SharpDevelop.
 * Пользователь: artem279
 * Дата: 17.10.2017
 * Время: 10:50
 */
using System;
using System.Collections;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Xml.Linq;

namespace cert_parser
{
	/// <summary>
	/// Библиотека для разбора сертификатов
	/// </summary>
	/// 

	public partial class CertInfo
	{

        public struct OidStruct
        {
           public string oid_type;
           public string oid_code;
           public string oid_value;
        }

		public string INN {get; set;}
		public string KPP {get; set;}
		public string OGRN {get; set;}
		public string OGRN2 {get; set;}
		public string SNILS {get; set;}
		public string CertHash {get; set;}
		//Common name of issuer
		public string CNuc {get; set;}
		public string CNholder {get; set;}
		public string CNuser {get; set;}
		public string Dolgnost {get; set;}
		public string Department {get; set;}
		public string region {get; set;}
		public string City {get; set;}
		public string Street {get; set;}
		public string EmailHolder {get; set; }
		public string DateSince {get; set;}
		public string DateExpiration {get; set;}
		public string SerialNumber {get; set;}
		//Base64 string
		public string sign {get; set;}
        //OIDs
        public List<OidStruct> OIDs { get; set; }


        public static byte[] Decode(string base64Encoded)
        {
            // According to http://www.tribridge.com/blog/crm/blogs/brandon-kelly/2011-04-29/Solving-OutOfMemoryException-errors-when-attempting-to-attach-large-Base64-encoded-content-into-CRM-annotations.aspx
            // System.Convert.ToBase64String may leak a lot of memory
            // An OpenPop user reported that OutOfMemoryExceptions were thrown, and supplied the following
            // code for the fix. This should not have memory leaks.
            // The code is nearly identical to the example on MSDN:
            // http://msdn.microsoft.com/en-us/library/system.security.cryptography.frombase64transform.aspx#exampleToggle
            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    base64Encoded = base64Encoded.Replace("\r\n", "");
                    base64Encoded = base64Encoded.Replace("\t", "");
                    base64Encoded = base64Encoded.Replace(" ", "");

                    byte[] inputBytes = Encoding.ASCII.GetBytes(base64Encoded);

                    using (FromBase64Transform transform = new FromBase64Transform(FromBase64TransformMode.DoNotIgnoreWhiteSpaces))
                    {
                        byte[] outputBytes = new byte[transform.OutputBlockSize];

                        // Transform the data in chunks the size of InputBlockSize.
                        const int inputBlockSize = 4;
                        int currentOffset = 0;
                        while (inputBytes.Length - currentOffset > inputBlockSize)
                        {
                            transform.TransformBlock(inputBytes, currentOffset, inputBlockSize, outputBytes, 0);
                            currentOffset += inputBlockSize;
                            memoryStream.Write(outputBytes, 0, transform.OutputBlockSize);
                        }

                        // Transform the final block of data.
                        outputBytes = transform.TransformFinalBlock(inputBytes, currentOffset, inputBytes.Length - currentOffset);
                        memoryStream.Write(outputBytes, 0, outputBytes.Length);
                    }

                    return memoryStream.ToArray();
                }
            }
            catch (FormatException e)
            {
                throw;
            }
        }


        /// <summary>
        /// Преобразует строку base64 в массив ArrayList
        /// </summary>
        /// <param name="sign"></param>
        /// <returns></returns>
        public ArrayList FromBase64(string sign)
		{

	    	ArrayList result = new ArrayList();
			byte[] encodedData;
            encodedData = Convert.FromBase64String(sign);
            X509Certificate2 cert = new X509Certificate2(encodedData);
			result.Add(cert.Issuer);
			result.Add(cert.Subject);
			result.Add(cert.NotBefore);
			result.Add(cert.NotAfter);
			result.Add(cert.Thumbprint);
			result.Add(cert.SerialNumber);
            result.Add(cert.Extensions);
            return result;
		}
		
		/// <summary>
		/// Разбирает файл сертификата и отдаёт массив ArrayList
		/// </summary>
		/// <param name="file"></param>
		/// <returns></returns>
		public ArrayList FromCertificate(string file)
		{
	    	
	    	ArrayList result = new ArrayList();
			X509Certificate2 cert = new X509Certificate2(file);
			result.Add(cert.Issuer);
			result.Add(cert.Subject);
			result.Add(cert.NotBefore);
			result.Add(cert.NotAfter);
			result.Add(cert.Thumbprint);
			result.Add(cert.SerialNumber);
            result.Add(cert.Extensions);
            return result;
		}
		
		public string strip(string inputstring)
		{
			return inputstring.Replace(";",",").Replace(", РНС", "").Replace("\\", "").Replace("|", "/").Replace("\"", "").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Trim().TrimStart(new char[] {','}).TrimEnd(new char[] {','});
		}
		

		/// <summary>
		/// Процедура обработки данных сертификата
		/// </summary>
		/// <param name="data">ArrayList</param>
		public void ParseData (ArrayList data)
		{
			//subject or issuer regexp
			Regex regexp = new Regex("([A-zА-я0-9\\.]*=)",RegexOptions.IgnoreCase);
			//OID regexp for requisites
			Regex oid_orgrequisites = new Regex("(OID)[.0-9]+=([A-zА-я\\=])*([0-9]{10,14})(\\/|\\-)?([A-zА-я\\=])*([0-9]{9})?(\\/|\\-)?([A-zА-я\\=])*([0-9]{15}|[0-9]{13}|[0-9]{11})?",RegexOptions.IgnoreCase);

			string [] issuer_matches = regexp.Split(data[0].ToString());
			var issuer = (from e in issuer_matches where strip(e) != "" select strip(e)).ToList();
            OIDs = new List<OidStruct>();
            //Разбираем данные УЦ
            for (int i = 0; i < issuer.Count; i++)
			{

                if (issuer[i].Contains("CN="))
                {
                    CNuc = issuer[i+1];
                    OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.3", oid_value = CNuc });
                }
                else if (issuer[i].Contains("O=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.10", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("OU=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.11", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("E=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.840.113549.1.9.1", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("ИНН=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.643.3.131.1.1", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("ОГРН=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.643.100.1", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("S=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.8", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("L=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.7", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("STREET=") | issuer[i].Contains("street=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.9", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("C=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.6", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("T=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.12", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("OID.1.2.840.113556.1.2.141=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.840.113556.1.2.141", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("Phone=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.643.3.131.1.1", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("SN=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.4", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("G=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.42", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("СНИЛС=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.643.100.3", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("I=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.43", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("Description=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "2.5.4.13", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("ФСС=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.643.3.141.1.1", oid_value = issuer[i + 1] }); }
                else if (issuer[i].Contains("1.2.840.113549.1.9.2=")) { OIDs.Add(new OidStruct { oid_type = "issuer", oid_code = "1.2.840.113549.1.9.2", oid_value = issuer[i + 1] }); }

            }
			
			string [] subject_matches = regexp.Split(data[1].ToString());
			var subject = (from e in subject_matches where strip(e) != "" select strip(e)).ToList();
			//(OID)[.0-9]+=([A-zА-я\=])*([0-9]{10,14})(\/|\-)?([A-zА-я\=])*([0-9]{9})?(\/|\-)?([A-zА-я\=])*([0-9]{15}|[0-9]{13}|[0-9]{11})?
			//Для красивой склейки орг. структуры
			List<string> department_list = new List<string>();
			
			//Подстраховка для реквизитов орг-ции (субъекта)
			MatchCollection matches = oid_orgrequisites.Matches(strip(data[1].ToString()));
			foreach(Match match in matches)
			{
				string [] oid_matches = regexp.Split(match.Value);
				var subject_oid = (from e in oid_matches where strip(e).Replace("/", "") != "" select strip(e).Replace("/", "")).ToList();
				for(int i = 0; i < subject_oid.Count; i++)
				{	
					if ((subject_oid[i].Contains("INN=") | subject_oid[i].Contains("ИНН=")) && String.IsNullOrEmpty(INN)) {	INN = subject_oid[i+1]; }
					else if ((subject_oid[i].Contains("KPP=") | subject_oid[i].Contains("КПП=")) && String.IsNullOrEmpty(KPP)) { KPP = subject_oid[i+1]; }
					else if ((subject_oid[i].Contains("OGRN=") | subject_oid[i].Contains("OGRNIP=") | subject_oid[i].Contains("ОГРН=") | subject_oid[i].Contains("ОГРНИП=")) && String.IsNullOrEmpty(OGRN)) { try { OGRN = subject_oid[i + 1]; } catch { OGRN = null; } }
				}
			}
			
			//Разбираем данные субъекта
			for(int i = 0; i < subject.Count; i++)
			{
				if ((subject[i].Contains("INN=") | subject[i].Contains("ИНН=")) && String.IsNullOrEmpty(INN)) {	INN = subject[i+1]; }
                if ((subject[i].Contains("INN=") | subject[i].Contains("ИНН="))) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.643.3.131.1.1", oid_value = subject[i + 1] }); }
                if ((subject[i].Contains("OGRN=") | subject[i].Contains("OGRNIP=") | subject[i].Contains("ОГРН=") | subject[i].Contains("ОГРНИП=")) && String.IsNullOrEmpty(OGRN)) { OGRN = subject[i + 1]; }
                if ((subject[i].Contains("OGRN=") | subject[i].Contains("OGRNIP=") | subject[i].Contains("ОГРН=") | subject[i].Contains("ОГРНИП="))) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.643.100.1", oid_value = subject[i + 1] }); }
                else if ((subject[i].Contains("KPP=") | subject[i].Contains("КПП=")) && String.IsNullOrEmpty(KPP)) { KPP = subject[i+1]; }
				
				else if ((subject[i].Contains("SNILS=") | subject[i].Contains("СНИЛС=")) && String.IsNullOrEmpty(SNILS)) { SNILS = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.643.100.3", oid_value = SNILS }); }
				else if (subject[i].Contains("street=")| subject[i].Contains("STREET=")) { Street = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.9", oid_value = Street }); }
				//Фамилия
				else if (subject[i].Contains("SN=")) { CNuser = subject[i+1]+" "+CNuser; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.4", oid_value = subject[i + 1] }); }
				//Имя и Отчество
				else if (subject[i].Contains("G=")) { CNuser += subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.42", oid_value = subject[i + 1] }); }
				//Владелец сертфииката (может быть юр. лицо!).
				else if (subject[i].Contains("CN=")) { CNholder = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.3", oid_value = CNholder }); }
				//Орг. структура
				else if (subject[i].Contains("OU="))
				{
                    OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.11", oid_value = subject[i + 1] });
                    if (!department_list.Contains(strip(subject[i+1])))	{ department_list.Add(strip(subject[i+1]));	}
				}
				else if (subject[i].Contains("S=")) { region = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.8", oid_value = region }); }
				else if (subject[i].Contains("L=")) { City = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.7", oid_value = City }); }
				else if (subject[i].Contains("T=")) { Dolgnost = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.12", oid_value = Dolgnost }); }
				else if (subject[i].Contains("E=")) { EmailHolder = subject[i+1]; OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.840.113549.1.9.1", oid_value = EmailHolder }); }
                else if (subject[i].Contains("I=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.43", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("Description=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.13", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("ФСС=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.643.3.141.1.1", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("1.2.840.113549.1.9.2=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.840.113549.1.9.2", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("OID.1.2.840.113556.1.2.141=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.840.113556.1.2.141", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("Phone=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "1.2.643.3.131.1.1", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("O=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.10", oid_value = subject[i + 1] }); }
                else if (subject[i].Contains("C=")) { OIDs.Add(new OidStruct { oid_type = "subject", oid_code = "2.5.4.6", oid_value = subject[i + 1] }); }

            }

            try
            {
                foreach (X509Extension extension in (X509ExtensionCollection)data[6])
                {
                    OIDs.Add(new OidStruct { oid_type = "extensions", oid_code = extension.Oid.Value, oid_value = "" });

                    if (extension.Oid.FriendlyName == "Enhanced Key Usage" | extension.Oid.FriendlyName == "Улучшенный ключ")
                    {
                        X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                        OidCollection oids = ext.EnhancedKeyUsages;
                        foreach (Oid oid in oids)
                        {
                            OIDs.Add(new OidStruct { oid_type = "extensions", oid_code = oid.Value, oid_value = "" });
                        }
                    }
                }
            }
            catch { Console.WriteLine("Has no extensions"); }
            

            Department = String.Join("; ", department_list);
			DateSince = data[2].ToString();
			DateExpiration = data[3].ToString();
			CertHash = data[4].ToString();
			SerialNumber = data[5].ToString();
				
		}
		
		/// <summary>
		/// Функция обработки контейнеров сертификатов из текстовых файлов (base64) 
		/// </summary>
		/// <param name="path">сканируемый каталог</param>
		/// <returns></returns>
		public static List<CertInfo> CertificateInfo(string path)
	    {
			List<CertInfo> certinfo = new List<CertInfo>();
	    	string sign = null;
	    	CertInfo cert = null;
	    	foreach(string f in Directory.GetFiles(path))
			{
				sign = File.ReadAllText(f);
				cert = new CertInfo();
				cert.ParseData(cert.FromBase64(sign));
				certinfo.Add(cert);
			}
	    	
	    	
			return certinfo;
		
		}

        
        /// <summary>
        /// Функция обработки контейнеров сертификатов (Base64string)
        /// </summary>
        /// <param name="Base64String">Строка Base64</param>
        /// <returns></returns>
        public static CertInfo CertificateInfoFromString(string Base64String)
        {
            CertInfo cert = new CertInfo();
            cert.ParseData(cert.FromBase64(Base64String));
            return cert;
        }

        /// <summary>
        /// Функция обработки контейнеров сертификатов из xml
        /// </summary>
        /// <param name="xmlfile">полный путь до xml</param>
        /// <param name="tagname">название тега, по которому будет вестись поиск</param>
        /// <returns>List of CertInfo</returns>
        public static List<CertInfo> CertificateInfo(string xmlfile, string tagname)
	    {
	    	
	    	List<CertInfo> certinfo = new List<CertInfo>();
    		FileInfo finfo = new FileInfo(xmlfile);
   			if(finfo.Extension == ".xml")
   			{
				XDocument doc = XDocument.Load(xmlfile);
				
				foreach (XElement row in doc.Root.Descendants(tagname))
				{
					CertInfo cert = new CertInfo();
					
					try
					{
						cert.sign = row.Value.Trim();
						cert.ParseData(cert.FromBase64(cert.sign));
					}
					catch
					{
						Console.WriteLine("Certificate is not exist!");
						continue;
					}
					
					certinfo.Add(cert);

				}

   			}

    		return certinfo;

	    }


        /// <summary>
		/// Функция обработки контейнеров сертификатов из объекта XDocument
		/// </summary>
		/// <param name="doc">XDocument объект</param>
        /// <param name="tagname">название тега, по которому будет вестись поиск</param>
		/// <returns></returns>
        public static List<CertInfo> CertificateInfo(XDocument doc, string tagname)
        {
            List<CertInfo> certinfo = new List<CertInfo>();
            foreach (XElement row in doc.Root.Descendants(tagname))
            {
                CertInfo cert = new CertInfo();

                try
                {
                    cert.sign = row.Value.Trim();
                    cert.ParseData(cert.FromBase64(cert.sign));
                }
                catch
                {
                    continue;
                }

                certinfo.Add(cert);

            }

            return certinfo;

        }


        /// <summary>
        /// Функция обработки сертификатов (*.cer)
        /// </summary>
        /// <param name="certfile">Путь до файла сертификата</param>
        /// <returns>CertInfo</returns>
        public static CertInfo CertificateInfoFromCerFile(string certfile)
	    {
	    	
    		FileInfo finfo = new FileInfo(certfile);
    		CertInfo cert = null;
   			if(finfo.Extension == ".cer")
   			{
   				cert = new CertInfo();
   				cert.ParseData(cert.FromCertificate(certfile));
   			}

    		return cert;
	    	
	    }

		
	}
}
