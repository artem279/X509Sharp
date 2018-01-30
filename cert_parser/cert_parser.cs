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
using System.Runtime.InteropServices;

namespace cert_parser
{
	/// <summary>
	/// Description of UserControl1.
	/// </summary>
	/// 
	[ComVisible(true)]
	public partial class CertInfo
	{
		public string INN {get; set;}
		public string KPP {get; set;}
		public string OGRN {get; set;}
		public string OGRN2 {get; set;}
		public string SNILS {get; set;}
		public string CertHash {get; set;}
		public string CNuc {get; set;}
		public string CNholder {get; set;}
		public string CNuser {get; set;}
		public string Dolgnost {get; set;}
		public string Department {get; set;}
		public string region {get; set;}
		public string City {get; set;}
		public string EmailHolder {get; set; }
		public string DateSince {get; set;}
		public string DateExpiration {get; set;}
		public string SerialNumber {get; set;}
		
		[ComVisible(true)]
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
		
		
		[ComVisible(true)]
		public void Subject (ArrayList data)
		{

			string [] parts = null;
				
				parts = data[0].ToString().Split(',');

				foreach(string p in parts)
				{
					
					if(p.Contains("CN="))
					{CNuc = p.Replace("CN=","").Trim().Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("\"","");}

				}
				
				parts = null;
				
				parts = data[1].ToString().Split(',');
				
				foreach(string p in parts)
				{
					
					if(p.Contains("OID"))
					{
						string[] OID = p.Trim().Replace("OID.1.2.840.113549.1.9.2=","").Replace("OID.1.2.643.3.131.1.1=","").Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("-","/").Replace("\"","").Replace("\\","/").Split('/');
						Regex regex = new Regex("(OID)[.0-9]+=([0-9]{10}|[0-9]{12})-([0-9]{9})?[-]?",RegexOptions.IgnoreCase);
						MatchCollection matches = regex.Matches(p);
						foreach(Match match in matches)
						{
							string[] estOID = match.Value.Trim().Replace("OID.1.2.840.113549.1.9.2=","").Replace("OID.1.2.643.3.131.1.1=","").Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("-","/").Replace("\"","").Replace("\\","/").Split('/');
							try { INN = estOID[0].Replace("INN=","").Replace("ИНН=","").Trim(); } catch{INN = "";}
							try { KPP = estOID[1].Replace("KPP=","").Replace("КПП=","").Trim(); } catch{KPP = "";}
						}
						try { if ((OID[0].Contains("ИНН") | OID[0].Contains("INN")) && String.IsNullOrEmpty(INN)) { INN = OID[0].Replace("INN=","").Replace("ИНН=","").Trim(); } } catch{INN = "";}
						try { if ((OID[1].Contains("КПП") | OID[1].Contains("KPP")) && String.IsNullOrEmpty(KPP)) { KPP = OID[1].Replace("KPP=","").Replace("КПП=","").Trim(); } } catch{KPP = "";}
						try { if(OID[2].Contains("ОГРН") | OID[2].Contains("OGRN") | OID[2].Contains("OGRNIP") | OID[2].Contains("ОГРНИП")) { OGRN = OID[2].Replace("OGRN=","").Replace("ОГРН=","").Replace("OGRNIP","").Replace("ОГРНИП","").Trim(); } } catch{OGRN = "";}
						
					}
					
					else if (p.Contains("SN=")) {CNuser = p.Replace("SN=","").Trim()+" "+CNuser;}
					else if (p.Contains("G=")) {CNuser += p.Replace("G=","").Trim();}
					else if (p.Contains("CN=")) {CNholder = p.Replace("CN=","").Trim();}
					else if (p.Contains("OU=")) {Department += p.Replace("OU=","").Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("\"","").Trim()+" ";}
					else if (p.Contains("S=")) {region = p.Replace("S=","").Trim().Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("\"","");}
					else if (p.Contains("L=")) {City = p.Replace("L=","").Trim().Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("\"","");}
					else if ((p.Contains("ИНН=")|p.Contains("INN=")) && String.IsNullOrEmpty(INN)) {try {int len = p.Length;} catch {INN = "";} if (p.Length > 4) {INN = p.Replace("ИНН=","").Replace("INN=","").Trim();}}
					else if ((p.Contains("КПП=")|p.Contains("KPP="))  && String.IsNullOrEmpty(KPP)) {try {int len = p.Length;} catch {KPP = "";} if (p.Length > 4) {KPP = p.Replace("КПП=","").Replace("KPP=","").Trim();}}
					else if (p.Contains("ОГРН=")  && String.IsNullOrEmpty(OGRN)) {OGRN2 = p.Replace("OGRN=","").Replace("ОГРН=","").Replace("OGRNIP","").Replace("ОГРНИП","").Trim();}
					else if (p.Contains("OGRN=") && String.IsNullOrEmpty(OGRN)) {OGRN2 = p.Replace("OGRN=","").Replace("ОГРН=","").Replace("OGRNIP","").Replace("ОГРНИП","").Trim();}
					else if (p.Contains("ОГРНИП") && String.IsNullOrEmpty(OGRN)) {OGRN2 = p.Replace("OGRN=","").Replace("ОГРН=","").Replace("OGRNIP","").Replace("ОГРНИП","").Trim();}
					//else if (p.Contains("SNILS=")) {SNILS = p.Replace("SNILS=","").Trim();}
					//else if (p.Contains("СНИЛС=")) {SNILS = p.Replace("СНИЛС=","").Trim();}
					else if (p.Contains("T=") && !p.Contains("ET=")) {Dolgnost = p.Replace("T=","").Trim();}
					else if (p.Contains("E=")) {EmailHolder = p.Replace("E=","").Trim().Replace(";"," ").Replace("\n"," ").Replace("\t", " ").Replace("NULL","").Replace("\"","");}
				}
				try { Department = Department.Trim(); } catch { Department = null; }
				DateSince = data[2].ToString();
				DateExpiration = data[3].ToString();
				CertHash = data[4].ToString();
				SerialNumber = data[5].ToString();
				
		}
		
		[ComVisible(true)]
		public static List<CertInfo> HolderInfo(string path)
	    {
			List<CertInfo> certinfo = new List<CertInfo>();
	    	string sign = null;
	    	CertInfo cert = null;
	    	foreach(string f in Directory.GetFiles(path))
			{
				sign = File.ReadAllText(f);
				
				cert = new CertInfo();
				//cert.file = f;
				cert.Subject(cert.FromBase64(sign));
				certinfo.Add(cert);
			}
	    	
	    	
			return certinfo;
		
		}
		
		
	}
}
