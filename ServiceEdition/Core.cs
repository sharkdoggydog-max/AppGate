using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using System.Management;

namespace AppGateServiceEdition {
 [DataContract] public class Rule {
  [DataMember] public string Name;
  [DataMember] public string Exe;
  [DataMember] public bool Enabled;
  [DataMember] public bool Allowed;
  public override string ToString(){return (Enabled?"● ":"○ ")+Name+" ("+Exe+")";}
 }
 [DataContract] public class Settings {
  [DataMember] public byte[] Salt;
  [DataMember] public byte[] Hash;
  [DataMember] public List<Rule> Rules=new List<Rule>();
 }
 [DataContract] public class Request {
  [DataMember] public string Command;
  [DataMember] public string Password;
  [DataMember] public string Value;
  [DataMember] public string Name;
 }
 [DataContract] public class Reply {
  [DataMember] public bool Ok;
  [DataMember] public string Message;
  [DataMember] public int RetryAfterSeconds;
  [DataMember] public bool StopGuard;
  [DataMember] public bool WindowMode;
  [DataMember] public bool GuardReady;
  [DataMember] public List<Rule> Rules;
 }
 static class Codec {
  public static byte[] Bytes<T>(T v){using(var m=new MemoryStream()){new DataContractJsonSerializer(typeof(T)).WriteObject(m,v);return m.ToArray();}}
  public static T Parse<T>(byte[] b){using(var m=new MemoryStream(b))return (T)new DataContractJsonSerializer(typeof(T)).ReadObject(m);}
  public static void Write<T>(Stream s,T v){byte[] b=Bytes(v);if(b.Length>32768)throw new IOException("Слишком большой запрос");byte[] size=BitConverter.GetBytes(b.Length);s.Write(size,0,4);s.Write(b,0,b.Length);s.Flush();}
  static byte[] ReadBytes(Stream s,int n){byte[] b=new byte[n];int pos=0;while(pos<n){int read=s.Read(b,pos,n-pos);if(read==0)throw new EndOfStreamException();pos+=read;}return b;}
  public static T Read<T>(Stream s){int n=BitConverter.ToInt32(ReadBytes(s,4),0);if(n<1||n>32768)throw new IOException("Недопустимый размер запроса");return Parse<T>(ReadBytes(s,n));}
 }
 static class Passwords {
  public static byte[] Hash(string p,byte[] salt){using(var k=new Rfc2898DeriveBytes(p,salt,210000,HashAlgorithmName.SHA256))return k.GetBytes(32);}
  public static void Set(Settings c,string p){if(p==null||p.Length<10||p.Length>256)throw new ArgumentException("Пароль: от 10 до 256 символов.");c.Salt=new byte[32];using(var r=RandomNumberGenerator.Create())r.GetBytes(c.Salt);c.Hash=Hash(p,c.Salt);}
  public static bool Check(Settings c,string p){if(p==null||p.Length>256)return false;byte[] hash=Hash(p,c.Salt);int d=hash.Length^c.Hash.Length;for(int i=0;i<hash.Length&&i<c.Hash.Length;i++)d|=hash[i]^c.Hash[i];return d==0;}
 }
 static class Store {
  public static string Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AppGateService");
  public static string FileName {get{return Path.Combine(Root,"settings.dat");}}
  public static void Save(Settings s){Directory.CreateDirectory(Root);byte[] bytes=ProtectedData.Protect(Codec.Bytes(s),null,DataProtectionScope.LocalMachine);string temp=FileName+".tmp";File.WriteAllBytes(temp,bytes);if(File.Exists(FileName))File.Replace(temp,FileName,null);else File.Move(temp,FileName);}
  public static Settings Load(){var s=Codec.Parse<Settings>(ProtectedData.Unprotect(File.ReadAllBytes(FileName),null,DataProtectionScope.LocalMachine));if(s.Salt==null||s.Salt.Length!=32||s.Hash==null||s.Hash.Length!=32||s.Rules==null)throw new IOException("Повреждены настройки");return s;}
  public static void Restrict(string dir,bool usersRead){Directory.CreateDirectory(dir);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);foreach(var sid in new[]{WellKnownSidType.LocalSystemSid,WellKnownSidType.BuiltinAdministratorsSid})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));if(usersRead)acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid,null),FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));Directory.SetAccessControl(dir,acl);}
 }
 static class Intercept {
  const string Base="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
  const string Owner="AppGateServiceOwner";
  public static string GatePath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"AppGateService","AppGateService.exe");
  public static string TestPipe;
  public static bool WindowMode;
  public static void Validate(string exe){
   string[] prohibited={"explorer.exe","cmd.exe","powershell.exe","pwsh.exe","reg.exe","regedit.exe","sc.exe","services.exe","svchost.exe","winlogon.exe","csrss.exe","lsass.exe","smss.exe","wininit.exe","taskmgr.exe","consent.exe","dllhost.exe","rundll32.exe","msiexec.exe","conhost.exe","runtimebroker.exe","userinit.exe","sihost.exe","dwm.exe","fontdrvhost.exe","wermgr.exe","werfault.exe"};
   if(string.IsNullOrEmpty(exe)||exe.Length>150||!exe.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)||exe.IndexOfAny(Path.GetInvalidFileNameChars())>=0||exe!=Path.GetFileName(exe)||exe.StartsWith("AppGate",StringComparison.OrdinalIgnoreCase)&&!exe.StartsWith("AppGateProbe_",StringComparison.OrdinalIgnoreCase)||prohibited.Contains(exe.ToLowerInvariant()))throw new ArgumentException("Выберите пользовательское приложение. Системные процессы и AppGate блокировать нельзя.");
  }
  static RegistryKey BaseKey(){return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64);}
  static string Command {get{return Native.Quote(GatePath)+(TestPipe==null?" --gate":" --test-gate "+TestPipe);}}
  public static bool IsOwned(string exe){using(var root=BaseKey())using(var k=root.OpenSubKey(Base+"\\"+exe))return k!=null && string.Equals(k.GetValue(Owner) as string,GatePath,StringComparison.OrdinalIgnoreCase);}
  public static void Set(string exe,bool enable){Validate(exe);if(WindowMode)enable=false;using(var root=BaseKey())using(var k=root.CreateSubKey(Base+"\\"+exe)){
   string debugger=k.GetValue("Debugger") as string;bool owned=string.Equals(k.GetValue(Owner) as string,GatePath,StringComparison.OrdinalIgnoreCase);
   if(enable){if((debugger!=null&&(!owned||!string.Equals(debugger,Command,StringComparison.OrdinalIgnoreCase)))||Convert.ToInt32(k.GetValue("UseFilter",0))!=0)throw new InvalidOperationException("Для этого exe уже заданы сторонние правила отладки. Они не изменены.");k.SetValue(Owner,GatePath);k.SetValue("Debugger",Command);}
   else if(owned){if(string.Equals(debugger,Command,StringComparison.OrdinalIgnoreCase))k.DeleteValue("Debugger",false);k.DeleteValue(Owner,false);}
  }}
  public static void Recover(){using(var root=BaseKey())using(var b=root.OpenSubKey(Base)){if(b==null)return;foreach(var name in b.GetSubKeyNames())if(IsOwned(name))Set(name,false);}}
 }
 class Failure {public int Count;public DateTime Until;}
 class Lease {public string Sid;public int Session;public string Exe;public DateTime Until;}
 class Engine : IDisposable {
  Settings settings;readonly object sync=new object();readonly Dictionary<string,Failure> failures=new Dictionary<string,Failure>();readonly List<Lease> leases=new List<Lease>();readonly List<NamedPipeServerStream> pipes=new List<NamedPipeServerStream>();volatile bool stopped;
  public Engine(Settings s){settings=s;}
  internal Func<DateTime> Now=()=>DateTime.UtcNow;
  volatile bool stoppingGuard;
  public void PrepareStop(){stoppingGuard=true;}
  public Func<int,bool> GuardAvailable=session=>false;
  public void Start(){for(int i=0;i<4;i++){var t=new Thread(Listen){IsBackground=true};t.Start();}new Thread(Monitor){IsBackground=true}.Start();}
  void Monitor(){while(!stopped){Thread.Sleep(400);lock(sync){foreach(var l in leases.ToArray()){
    bool found=false;foreach(var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(l.Exe)))using(p){try{if(p.SessionId==l.Session){found=true;break;}}catch{}}
    if(found)l.Until=DateTime.UtcNow.AddSeconds(2);else if(l.Until<DateTime.UtcNow)leases.Remove(l);
  }}}}
  bool Authenticate(string sid,string password){Failure f;if(!failures.TryGetValue(sid,out f)){f=new Failure();failures[sid]=f;}if(Now()<f.Until)return false;if(f.Until!=default(DateTime)){f.Count=0;f.Until=default(DateTime);}if(Passwords.Check(settings,password)){failures.Remove(sid);return true;}if(++f.Count>=5)f.Until=Now().AddSeconds(30);return false;}
  Reply AuthError(string sid){Failure f;if(failures.TryGetValue(sid,out f)&&f.Until>Now()){int sec=(int)Math.Ceiling((f.Until-Now()).TotalSeconds);return new Reply{Message="Слишком много ошибок. Повторите через "+sec+" сек.",RetryAfterSeconds=sec};}return No("Неверный текущий пароль AppGate. Проверьте раскладку и Caps Lock.");}
  public Reply Handle(Request q,string sid,int session){lock(sync){
   if(q==null||q.Command==null)return No("Пустой запрос");
   if(q.Command=="watch"&&stoppingGuard)return new Reply{Ok=true,StopGuard=true};
   if(q.Command=="lock"){leases.RemoveAll(l=>l.Sid==sid&&l.Session==session&&string.Equals(l.Exe,q.Value,StringComparison.OrdinalIgnoreCase));return Yes();}
   if(q.Command=="list"||q.Command=="watch")return new Reply{Ok=true,WindowMode=Intercept.WindowMode,GuardReady=GuardAvailable(session),Rules=settings.Rules.Select(r=>new Rule{Name=r.Name,Exe=r.Exe,Enabled=r.Enabled,Allowed=leases.Any(l=>l.Sid==sid&&l.Session==session&&string.Equals(l.Exe,r.Exe,StringComparison.OrdinalIgnoreCase)&&l.Until>DateTime.UtcNow)}).ToList()};
   if(q.Command=="open"){
    // An explicit shortcut click ALWAYS verifies the password, even with a live lease.
    if(!Authenticate(sid,q.Password))return AuthError(sid);
    string exe=Path.GetFileName(q.Value??"");var rule=settings.Rules.FirstOrDefault(r=>string.Equals(r.Exe,exe,StringComparison.OrdinalIgnoreCase));if(rule==null)return No("Сначала добавьте приложение в AppGate.");
    if(!rule.Enabled){Intercept.Set(rule.Exe,true);try{rule.Enabled=true;Store.Save(settings);}catch{rule.Enabled=false;Intercept.Set(rule.Exe,false);throw;}}
    leases.RemoveAll(l=>l.Sid==sid&&l.Session==session&&string.Equals(l.Exe,exe,StringComparison.OrdinalIgnoreCase));leases.Add(new Lease{Sid=sid,Session=session,Exe=exe,Until=DateTime.UtcNow.AddSeconds(15)});return Yes();
   }
   if(q.Command=="gate"||q.Command=="allow"||q.Command=="gate-entry"||q.Command=="allow-entry"){
    string exe=Path.GetFileName(q.Value??"");var rule=settings.Rules.FirstOrDefault(r=>r.Enabled&&string.Equals(r.Exe,exe,StringComparison.OrdinalIgnoreCase));if(rule==null)return No("Для приложения нет активного правила. Откройте настройки AppGate.");
    bool entry=q.Command.EndsWith("-entry",StringComparison.Ordinal);
    if((!entry||q.Name=="verified-child")&&leases.Any(l=>l.Sid==sid&&l.Session==session&&string.Equals(l.Exe,exe,StringComparison.OrdinalIgnoreCase)&&l.Until>DateTime.UtcNow))return Yes();
    if(q.Command=="gate"||q.Command=="gate-entry")return No("Требуется пароль");
    if(!Authenticate(sid,q.Password))return AuthError(sid);
    leases.Add(new Lease{Sid=sid,Session=session,Exe=exe,Until=DateTime.UtcNow.AddSeconds(15)});return Yes();
   }
   if(!Authenticate(sid,q.Password))return AuthError(sid);
   if(q.Command=="auth")return Yes();
   if(q.Command=="password"){var replacement=new Settings{Rules=settings.Rules};Passwords.Set(replacement,q.Value);Store.Save(replacement);settings=replacement;leases.Clear();failures.Clear();return Yes();}
   if(q.Command=="add"){
    string path=Path.GetFullPath(q.Value);if(!File.Exists(path)||path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows)+"\\",StringComparison.OrdinalIgnoreCase))return No("Выберите существующий exe вне системной папки Windows.");string exe=Path.GetFileName(path);Intercept.Validate(exe);if(settings.Rules.Any(r=>string.Equals(r.Exe,exe,StringComparison.OrdinalIgnoreCase)))return No("Это имя exe уже добавлено.");if(settings.Rules.Count>=100)return No("Максимум 100 приложений.");settings.Rules.Add(new Rule{Name=Path.GetFileNameWithoutExtension(exe),Exe=exe});Store.Save(settings);return Yes();
   }
   var target=settings.Rules.FirstOrDefault(r=>string.Equals(r.Exe,q.Value,StringComparison.OrdinalIgnoreCase));if(target==null)return No("Правило не найдено");
   if(q.Command=="toggle"){
    bool before=target.Enabled;Intercept.Set(target.Exe,!before);try{target.Enabled=!before;Store.Save(settings);}catch{target.Enabled=before;Intercept.Set(target.Exe,before);throw;}leases.RemoveAll(l=>string.Equals(l.Exe,target.Exe,StringComparison.OrdinalIgnoreCase));return Yes();
   }
   if(q.Command=="remove"){if(target.Enabled)return No("Сначала выключите защиту этого приложения.");settings.Rules.Remove(target);Store.Save(settings);return Yes();}
   return No("Неизвестная команда");
  }}
  static Reply Yes(){return new Reply{Ok=true};}static Reply No(string m){return new Reply{Message=m};}
  void Listen(){while(!stopped){
   var acl=new PipeSecurity();acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid,null),PipeAccessRights.ReadWrite,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));acl.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User,PipeAccessRights.FullControl,AccessControlType.Allow));
   try{using(var p=new NamedPipeServerStream(Client.PipeName,PipeDirection.InOut,4,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,32768,32768,acl)){
    lock(pipes){if(stopped)return;pipes.Add(p);}try{var wait=p.BeginWaitForConnection(null,null);using(var handle=wait.AsyncWaitHandle){while(!stopped&&!wait.IsCompleted)handle.WaitOne(100);if(stopped)return;p.EndWaitForConnection(wait);}using(var deadline=new System.Threading.Timer(o=>{try{p.Dispose();}catch{}},null,8000,Timeout.Infinite)){
     Request q=Codec.Read<Request>(p);uint pid;if(!Native.GetNamedPipeClientProcessId(p.SafePipeHandle.DangerousGetHandle(),out pid))throw new IOException("Не удалось определить клиента");string sid=null;p.RunAsClient(()=>sid=WindowsIdentity.GetCurrent().User.Value);int session;using(var process=Process.GetProcessById((int)pid))session=process.SessionId;
     if(q!=null){q.Name=null;if(q.Command=="gate-entry"||q.Command=="allow-entry")try{using(var parentInfo=new ManagementObject("Win32_Process.Handle='"+pid+"'")){parentInfo.Get();int parentId=Convert.ToInt32(parentInfo["ParentProcessId"]);using(var parent=Process.GetProcessById(parentId))using(var caller=Process.GetProcessById((int)pid)){if(parent.SessionId==session&&parent.StartTime<=caller.StartTime&&string.Equals(Native.ProcessPath(parentId),q.Value,StringComparison.OrdinalIgnoreCase))q.Name="verified-child";}}}catch{}}
     Reply r;try{r=Handle(q,sid,session);}catch(Exception ex){r=No(ex.Message);}if(q!=null)q.Password=null;Codec.Write(p,r);
    }}finally{lock(pipes)pipes.Remove(p);}
   }}catch(Exception ex){if(!stopped){try{File.WriteAllText(Path.Combine(Store.Root,"last-error.txt"),DateTime.UtcNow.ToString("O")+" "+ex.GetType().Name+": "+ex.Message);}catch{}Thread.Sleep(100);}}
  }}
  public void Dispose(){stopped=true;lock(pipes)foreach(var p in pipes.ToArray())try{p.Dispose();}catch{}}
 }
 static class Client {
  public static string PipeName="AppGateService.v2";
  public static int LastServerPid;
  public static Reply Send(Request q){using(var p=new NamedPipeClientStream(".",PipeName,PipeDirection.InOut,PipeOptions.None,TokenImpersonationLevel.Impersonation)){
   p.Connect(2500);uint server;if(!Native.GetNamedPipeServerProcessId(p.SafePipeHandle.DangerousGetHandle(),out server))throw new IOException("Служба не подтверждена");LastServerPid=(int)server;
   if(PipeName=="AppGateService.v2"){using(var proc=Process.GetProcessById((int)server)){if(!string.Equals(Native.ProcessPath(proc.Id),Intercept.GatePath,StringComparison.OrdinalIgnoreCase)||proc.SessionId!=0)throw new IOException("Недоверенный сервер AppGate");}}
   using(var timer=new System.Threading.Timer(o=>{try{p.Dispose();}catch{}},null,8000,Timeout.Infinite)){Codec.Write(p,q);return Codec.Read<Reply>(p);}
  }}
 }
 static class Native {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetPackagesByPackageFamily(string family,ref uint count,IntPtr names,ref uint chars,IntPtr buffer);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern int GetPackagePathByFullName(string name,ref uint chars,StringBuilder path);
  public static string CodexPath(){
   uint count=0,chars=0;int rc=GetPackagesByPackageFamily("OpenAI.Codex_2p2nqsd0c76g0",ref count,IntPtr.Zero,ref chars,IntPtr.Zero);if(count==0||(rc!=0&&rc!=122))throw new IOException("Codex не установлен для этого пользователя Windows.");
   IntPtr names=Marshal.AllocHGlobal(checked((int)count*IntPtr.Size)),buffer=Marshal.AllocHGlobal(checked((int)chars*2));
   try{rc=GetPackagesByPackageFamily("OpenAI.Codex_2p2nqsd0c76g0",ref count,names,ref chars,buffer);if(rc!=0)throw new System.ComponentModel.Win32Exception(rc);
    for(int i=0;i<count;i++){string name=Marshal.PtrToStringUni(Marshal.ReadIntPtr(names,i*IntPtr.Size));uint len=0;rc=GetPackagePathByFullName(name,ref len,null);if(rc!=122)continue;var path=new StringBuilder((int)len);if(GetPackagePathByFullName(name,ref len,path)!=0)continue;string exe=Path.Combine(path.ToString(),"app","ChatGPT.exe");if(File.Exists(exe))return exe;}
   }finally{Marshal.FreeHGlobal(names);Marshal.FreeHGlobal(buffer);}throw new IOException("Не удалось найти ChatGPT.exe в установленном пакете Codex.");
  }
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeClientProcessId(IntPtr pipe,out uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GetNamedPipeServerProcessId(IntPtr pipe,out uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr p,int flags,StringBuilder path,ref int size);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static string ProcessPath(int pid){IntPtr p=OpenProcess(0x1000,false,pid);if(p==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();try{var s=new StringBuilder(32768);int len=s.Capacity;if(!QueryFullProcessImageName(p,0,s,ref len))throw new System.ComponentModel.Win32Exception();return s.ToString();}finally{CloseHandle(p);}}
  public static string Quote(string s){if(s==null)return "\"\"";var b=new StringBuilder("\"");int slash=0;foreach(char c in s){if(c=='\\'){slash++;continue;}if(c=='\"'){b.Append('\\',slash*2+1);b.Append(c);}else{b.Append('\\',slash);b.Append(c);}slash=0;}b.Append('\\',slash*2);b.Append('"');return b.ToString();}
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public int cb;public string reserved,desktop,title;public int x,y,xSize,ySize,xChars,yChars,fill,flags;public short show,reserved2;public IntPtr reservedPtr,input,output,error;}
  [StructLayout(LayoutKind.Sequential)] struct Info {public IntPtr process,thread;public uint pid,tid;}
  [StructLayout(LayoutKind.Explicit,Size=176)] struct DebugEvent { [FieldOffset(0)] public uint code;[FieldOffset(4)]public uint pid;[FieldOffset(8)]public uint tid;[FieldOffset(16)]public IntPtr file; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string dir,ref Startup startup,out Info info);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool WaitForDebugEvent(out DebugEvent e,uint ms);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ContinueDebugEvent(uint pid,uint tid,uint status);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugActiveProcessStop(uint pid);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugSetProcessKillOnExit(bool kill);
  [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr p,uint code);
  public static string DiagnoseLaunch(string exe){var s=new Startup{cb=Marshal.SizeOf(typeof(Startup))};Info p;bool ok=CreateProcess(exe,new StringBuilder(Quote(exe)),IntPtr.Zero,IntPtr.Zero,false,6,IntPtr.Zero,Path.GetDirectoryName(exe),ref s,out p);if(!ok){int code=Marshal.GetLastWin32Error();return "CreateProcess DEBUG_ONLY_THIS_PROCESS + CREATE_SUSPENDED: Win32="+code+" "+new System.ComponentModel.Win32Exception(code).Message;}try{TerminateProcess(p.process,1);return "Suspended creation succeeded; terminated without resuming.";}finally{CloseHandle(p.thread);CloseHandle(p.process);}}
  public static int Launch(string[] args){if(args.Length==0||!Path.IsPathRooted(args[0])||!File.Exists(args[0]))throw new IOException("Windows не передала полный путь приложения.");var s=new Startup{cb=Marshal.SizeOf(typeof(Startup))};Info p;
   if(!CreateProcess(args[0],new StringBuilder(string.Join(" ",args.Select(Quote))),IntPtr.Zero,IntPtr.Zero,true,2,IntPtr.Zero,Environment.CurrentDirectory,ref s,out p))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   bool detached=false;try{DebugEvent e;if(!WaitForDebugEvent(out e,5000))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());if(e.code==3&&e.file!=IntPtr.Zero)CloseHandle(e.file);if(!ContinueDebugEvent(e.pid,e.tid,0x00010002))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());if(!DebugActiveProcessStop(p.pid))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());detached=true;DebugSetProcessKillOnExit(false);return (int)p.pid;}finally{if(!detached)TerminateProcess(p.process,1);CloseHandle(p.thread);CloseHandle(p.process);}
  }
 }
}
