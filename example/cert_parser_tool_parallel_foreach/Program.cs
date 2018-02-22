/*
 * Создано в SharpDevelop.
 * Пользователь: artem279
 * Дата: 20.02.2018
 * Время: 12:04
 * 
 * Для изменения этого шаблона используйте меню "Инструменты | Параметры | Кодирование | Стандартные заголовки".
 */
using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using cert_parser;

namespace cert_parser_tool_parallel_foreach
{
	class Program
	{
		
		//глобальная переменная для хранения списка файлов к обработке
		public static List<string> files = new List<string>();
		
		/// <summary>
		/// Получает список всех xml-файлов из заданной директории, включая подкаталоги
		/// </summary>
		/// <param name="dir">стартовый каталог</param>
		/// <returns>List of strings</returns>
		public static List<string> GetFileInSubDir(string dir)
		{
			string file = "";
			foreach (string f in Directory.GetFiles(dir))
			{
				FileInfo fi = new FileInfo(f);
				if(fi.Extension == ".xml")
				{
					Console.WriteLine("Добавляем файл в коллекцию: {0}",f);
					file = f;
					files.Add(file);
				}
			}
			
			foreach (string d in Directory.GetDirectories(dir))
			{
				GetFileInSubDir(d);
			}
			
			return files;
		}
		
		
		/// <summary>
		/// Процедура-обработчик
		/// </summary>
		/// <param name="file">имя файла</param>
		/// <param name="mut">мьютекс</param>
		/// <param name="workpath">рабочая директория программы</param>
		public static void ThreadProcess(string file, Mutex mut, string workpath)
        {
            try
			{
				List<CertInfo> certinfo = new List<CertInfo>();
				certinfo = CertInfo.CertificateInfo(file, "sign");
				mut.WaitOne();
				Thread.Sleep(50);
				using (StreamWriter writer = new StreamWriter(workpath + "data.csv", true, Encoding.Default))
				{
					foreach(var e in certinfo)
					{
						Console.WriteLine("{0} {1}", e.CNuc, e.CertHash);
						writer.WriteLine(e.CNuc+"|"+e.INN+"|"+e.KPP+"|"+e.OGRN+"|"+e.SNILS+"|"+e.CertHash+"|"+e.SerialNumber+"|"+e.DateSince+"|"+e.DateExpiration+"|"+
						                e.CNholder+"|"+e.CNuser+"|"+e.Department+"|"+e.Dolgnost+"|"+e.EmailHolder+"|"+e.region+"|"+e.City+"|"+e.Street+"|"+e.sign);
						writer.Flush();
					}
					
				}
				Console.WriteLine("Thread is done!");
				mut.ReleaseMutex();
			}
            catch {	Console.WriteLine("Something wrong!"); }
        }
		
		public static void Main(string[] args)
		{
			Mutex mut = new Mutex();
			//задаём рабочую директорию
			string path = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)+"\\";
			//объявляем необходимое кол-во одновременно работающих потоков
			int numthreads = 15;
			Stopwatch watch = new Stopwatch();
			//заполняем список
			List<string> lst = GetFileInSubDir("C:\\xmlpath\\");
			//запускаем таймер и хост-процедуру
			watch.Start();
			Parallel.ForEach(lst, new ParallelOptions {MaxDegreeOfParallelism = numthreads}, file => ThreadProcess(file, mut, path));
			watch.Stop();
			TimeSpan ts = watch.Elapsed;
        	string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds / 10);
        	Console.WriteLine("RunTime " + elapsedTime);
        	File.AppendAllText(Path.Combine(path, "timelog.log"), "Runtime: " + elapsedTime + Environment.NewLine, Encoding.Default);
			Console.Write("Press any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}