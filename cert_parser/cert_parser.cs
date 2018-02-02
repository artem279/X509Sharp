/*
 * Создано в SharpDevelop.
 * Пользователь: artem279
 * Дата: 17.10.2017
 * Время: 10:50
 */
using System;
using System.Collections;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Xml.Linq;

namespace cert_parser
{
	/// <summary>
	/// Description of UserControl1.
	/// </summary>
	/// 

	public partial class CertInfo
	{
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
	    	return result;
		}
		
		
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
	    	return result;
		}
		
		public string strip(string inputstring)
		{
			return inputstring.Replace(";",",").Replace("\\", "").Replace("|", "/").Replace("\"", "").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Trim().TrimStart(new char[] {','}).TrimEnd(new char[] {','});
		}
		
		
		public void ParseData (ArrayList data)
		{
			//subject or issuer regexp
			Regex regexp = new Regex("([A-zА-я0-9\\.]*=)",RegexOptions.IgnoreCase);
			//OID regexp for requisites
			Regex oid_orgrequisites = new Regex("(OID)[.0-9]+=([A-zА-я\\=])*([0-9]{10,14})(\\/|\\-)?([A-zА-я\\=])*([0-9]{9})?(\\/|\\-)?([A-zА-я\\=])*([0-9]{15}|[0-9]{13}|[0-9]{11})?",RegexOptions.IgnoreCase);

			string [] issuer_matches = regexp.Split(data[0].ToString());
			var issuer = (from e in issuer_matches where strip(e) != "" select strip(e)).ToList();
			
			//Разбираем данные УЦ
			for(int i = 0; i < issuer.Count; i++)
			{
				if (issuer[i].Contains("CN=")) {CNuc = issuer[i+1];}
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
					else if ((subject_oid[i].Contains("OGRN=") | subject_oid[i].Contains("OGRNIP=") | subject_oid[i].Contains("ОГРН=") | subject_oid[i].Contains("ОГРНИП=")) && String.IsNullOrEmpty(OGRN)) { OGRN = subject_oid[i+1]; }
				}
			}
			
			//Разбираем данные субъекта
			for(int i = 0; i < subject.Count; i++)
			{
				if ((subject[i].Contains("INN=") | subject[i].Contains("ИНН=")) && String.IsNullOrEmpty(INN)) {	INN = subject[i+1]; }
				else if ((subject[i].Contains("KPP=") | subject[i].Contains("КПП=")) && String.IsNullOrEmpty(KPP)) { KPP = subject[i+1]; }
				else if ((subject[i].Contains("OGRN=") | subject[i].Contains("OGRNIP=") | subject[i].Contains("ОГРН=") | subject[i].Contains("ОГРНИП=")) && String.IsNullOrEmpty(OGRN)) { OGRN = subject[i+1]; }
				else if ((subject[i].Contains("SNILS=") | subject[i].Contains("СНИЛС=")) && String.IsNullOrEmpty(SNILS)) { SNILS = subject[i+1]; }
				else if (subject[i].Contains("street=")|subject[i].Contains("STREET="))	{ Street = subject[i+1]; }
				//Фамилия
				else if (subject[i].Contains("SN=")) {CNuser = subject[i+1]+" "+CNuser;}
				//Имя и Отчество
				else if (subject[i].Contains("G=")) {CNuser += subject[i+1];}
				//Владелец сертфииката (может быть юр. лицо!).
				else if (subject[i].Contains("CN=")) {CNholder = subject[i+1];}
				//Орг. структура
				else if (subject[i].Contains("OU="))
				{
					if (!department_list.Contains(strip(subject[i+1])))
					{
						department_list.Add(strip(subject[i+1]));
					}
				}
				else if (subject[i].Contains("S=")) {region = subject[i+1];}
				else if (subject[i].Contains("L=")) {City = subject[i+1];}
				else if (subject[i].Contains("T=")) {Dolgnost = subject[i+1];}
				else if (subject[i].Contains("E=")) {EmailHolder = subject[i+1];}
				
			}
			
			Department = String.Join("; ", department_list);
			DateSince = data[2].ToString();
			DateExpiration = data[3].ToString();
			CertHash = data[4].ToString();
			SerialNumber = data[5].ToString();
				
		}
		

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
