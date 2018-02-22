/*
 * Создано в SharpDevelop.
 * Пользователь: artem279
 * Дата: 16.02.2018
 * Время: 10:03
 * 
 * Для изменения этого шаблона используйте меню "Инструменты | Параметры | Кодирование | Стандартные заголовки".
 */
using System;
using System.Text;
using System.IO;
using System.Collections.Generic;
using System.Threading;
using System.Diagnostics;
using cert_parser;

namespace cert_parser_tool_threadpool
{
	
	public struct StateInfo
	{
		public string filename; //file
		public string wpath; //workpath
		public Mutex locker; //mutex (lock object)
	}
	
	class Program
	{
		
		//глобальная переменная для хранения списка файлов к обработке
		static List<string> files = new List<string>();
		
		//сигнал для потока
		static ManualResetEvent _doneEvent = new ManualResetEvent(false);
		
		//Общее кол-во потоков к обработке
		static int numberOfThreads;
		
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
		static void ThreadProcess(Object stateInfo)
        {
			StateInfo s = (StateInfo)stateInfo;
			try
			{
				List<CertInfo> certinfo = new List<CertInfo>();
				certinfo = CertInfo.CertificateInfo(s.filename, "sign");
				s.locker.WaitOne();
					Thread.Sleep(5);
					using (StreamWriter writer = new StreamWriter(s.wpath + "data.csv", true, Encoding.Default))
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
				s.locker.ReleaseMutex();
			}
			catch { Console.WriteLine("Something wrong!"); }
			finally { if (Interlocked.Decrement(ref numberOfThreads) == 0) { _doneEvent.Set(); } }
			
        }
		
		
		/// <summary>
		/// Хост-процедура
		/// </summary>
		/// <param name="numthreads">Кол-во одновременно работающих потоков (максимальное кол-во потоков)</param>
		/// <param name="fileslist">список файлов к обработке</param>
		/// <param name="workpath">рабочая директория программы</param>
		public static void createthreadparser(int numthreads, List<string> fileslist, string workpath)
		{
			Mutex mut = new Mutex();
			ThreadPool.SetMaxThreads(numthreads, numthreads);
			ThreadPool.SetMinThreads(numthreads, numthreads);
			
			numberOfThreads = fileslist.Count;
			
			foreach (var file in fileslist)
			{
				StateInfo s = new StateInfo {wpath = workpath, locker = mut, filename = file};
				ThreadPool.QueueUserWorkItem(new WaitCallback(ThreadProcess), (object)s);
			}
			
			_doneEvent.WaitOne();
		}
		
		public static void Main(string[] args)
		{
			//задаём рабочую директорию
			string path = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location)+"\\";
			//Объявляем список
			List<string> lst = new List<string>();

			Stopwatch watch = new Stopwatch();
			
			//заполняем список
			lst = GetFileInSubDir("C:\\xmlpath\\");

			//запускаем таймер и хост-процедуру
			watch.Start();
			createthreadparser(15, lst, path);
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