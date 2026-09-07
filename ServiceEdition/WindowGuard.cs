using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace AppGateServiceEdition {
 // Window privacy lock, not a pre-execution security boundary. No target relaunch,
 // debugger, code injection, or modification of application shortcuts is involved.
 sealed class WindowGuard : ApplicationContext {
  readonly string HiddenProperty="AppGate.WindowLock.v3."+Client.PipeName;
  readonly Control dispatch=new Control();
  readonly System.Windows.Forms.Timer scan=new System.Windows.Forms.Timer{Interval=100};
  readonly Dictionary<IntPtr,string> hidden=new Dictionary<IntPtr,string>();
  readonly HashSet<string> dismissed=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  readonly HashSet<string> seenWindows=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  readonly HashSet<string> relock=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  readonly int ownPid=Process.GetCurrentProcess().Id;
  List<Rule> rules=new List<Rule>();
  PasswordDialog prompt;
  string prompting;
  bool polling,closing;
  int authRevision;
  DateTime nextPoll;
  readonly WindowApi.EventCallback callback;
  readonly List<IntPtr> hooks=new List<IntPtr>();
  internal Func<Request,Reply> Send=Client.Send;
  internal PasswordDialog ActivePrompt {get{return prompt;}}
  internal int ParentPid;
  public WindowGuard(){
   var handle=dispatch.Handle;
   callback=OnEvent;
   hooks.Add(WindowApi.SetWinEventHook(0x8002,0x8002,IntPtr.Zero,callback,0,0,2)); // SHOW, skip self
   hooks.Add(WindowApi.SetWinEventHook(3,3,IntPtr.Zero,callback,0,0,2)); // foreground
   if(hooks.Any(h=>h==IntPtr.Zero))throw new Win32Exception();
   scan.Tick+=(s,e)=>Tick();scan.Start();
  }
  void OnEvent(IntPtr hook,uint kind,IntPtr window,int obj,int child,uint thread,uint time){
   if(closing||window==IntPtr.Zero||obj!=0||child!=0)return;
   string exe=Executable(window);if(exe==null)return;
   if(IsLocked(exe)&&WindowApi.IsWindowVisible(window)){dismissed.Remove(exe);Check(window,exe);ShowNext();}
  }
  string Executable(IntPtr window){
   if(WindowApi.GetAncestor(window,2)!=window)return null;
   uint pid;WindowApi.GetWindowThreadProcessId(window,out pid);
   if(pid==ownPid)return null;
   try{using(var p=Process.GetProcessById((int)pid))return p.ProcessName+".exe";}catch{return null;}
  }
  bool IsLocked(string exe){return rules.Any(r=>r.Enabled&&!r.Allowed&&string.Equals(r.Exe,exe,StringComparison.OrdinalIgnoreCase));}
  void Check(IntPtr window,string exe){
   bool marked=WindowApi.GetProp(window,HiddenProperty)!=IntPtr.Zero;
   if(!IsLocked(exe)){
    if(marked){WindowApi.RemoveProp(window,HiddenProperty);hidden.Remove(window);WindowApi.ShowWindowAsync(window,5);}
    return;
   }
   if(marked)hidden[window]=exe;
   if(WindowApi.IsWindowVisible(window)){
    dismissed.Remove(exe);
    // Keep a marker on the target window so a replacement agent can recover it.
    if(!WindowApi.SetProp(window,HiddenProperty,new IntPtr(1)))return;
    hidden[window]=exe;WindowApi.ShowWindowAsync(window,0);
   }
  }
  void Tick(){
   if(closing)return;
   if(ParentPid!=0){try{using(var parent=Process.GetProcessById(ParentPid))if(parent.HasExited){ExitThread();return;}}catch(ArgumentException){ExitThread();return;}}
   if(!polling&&DateTime.UtcNow>=nextPoll){
    polling=true;nextPoll=DateTime.UtcNow.AddMilliseconds(300);
    int revision=authRevision;
    string[] revoke=relock.ToArray();relock.Clear();
    ThreadPool.QueueUserWorkItem(o=>{
     Reply reply=null;try{foreach(var exe in revoke)Send(new Request{Command="lock",Value=exe});reply=Send(new Request{Command="watch"});}catch{}
     try{dispatch.BeginInvoke((Action)(()=>{
      polling=false;if(closing)return;
      if(reply==null)foreach(var exe in revoke)relock.Add(exe);
      if(reply!=null&&reply.Ok&&reply.StopGuard){RestoreAll();ExitThread();return;}
      if(revision!=authRevision)return;
      if(reply!=null&&reply.Ok&&reply.Rules!=null)rules=reply.Rules;
      else foreach(var r in rules)r.Allowed=false; // retain known protections during outage
      Sweep();
     }));}catch(InvalidOperationException){}
    });
   }
   Sweep();
  }
  void RestoreAll(){
   closing=true;
   WindowApi.EnumWindows((w,p)=>{if(WindowApi.GetProp(w,HiddenProperty)!=IntPtr.Zero){WindowApi.RemoveProp(w,HiddenProperty);WindowApi.ShowWindowAsync(w,5);}return true;},IntPtr.Zero);
  }
  void Sweep(){
   var present=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
   WindowApi.EnumWindows((w,p)=>{string exe=Executable(w);if(exe!=null){if(WindowApi.IsWindowVisible(w)||WindowApi.GetProp(w,HiddenProperty)!=IntPtr.Zero)present.Add(exe);Check(w,exe);}return true;},IntPtr.Zero);
   foreach(var r in rules){if(present.Contains(r.Exe))seenWindows.Add(r.Exe);else if(seenWindows.Remove(r.Exe)&&r.Allowed){r.Allowed=false;authRevision++;relock.Add(r.Exe);}}
   foreach(var w in hidden.Keys.ToArray())if(!WindowApi.IsWindow(w))hidden.Remove(w);
   if(prompt!=null&&!IsLocked(prompting)){prompt.Close();}
   ShowNext();
  }
  void ShowNext(){
   if(closing||prompt!=null)return;
   string exe=hidden.Values.FirstOrDefault(x=>IsLocked(x)&&!dismissed.Contains(x));if(exe==null)return;
   prompting=exe;
   prompt=new PasswordDialog("AppGate — разблокировать "+exe,false,p=>Send(new Request{Command="allow",Value=exe,Password=p}),"Пароль для доступа к "+exe);
   prompt.Verified+=()=>{authRevision++;foreach(var r in rules)if(string.Equals(r.Exe,exe,StringComparison.OrdinalIgnoreCase))r.Allowed=true;nextPoll=DateTime.UtcNow.AddMilliseconds(500);};
   prompt.FormClosed+=(s,e)=>{
    var old=prompt;prompt=null;prompting=null;
    if(old.DialogResult!=DialogResult.OK&&IsLocked(exe)){
     dismissed.Add(exe);
     // Ask the target to close normally: never discard unsaved work by killing it.
     foreach(var w in hidden.Where(x=>string.Equals(x.Value,exe,StringComparison.OrdinalIgnoreCase)).Select(x=>x.Key).ToArray())WindowApi.PostMessage(w,0x10,IntPtr.Zero,IntPtr.Zero);
    }
    old.Dispose();
   };
   prompt.Show();
  }
  protected override void Dispose(bool disposing){
   closing=true;scan.Stop();scan.Dispose();foreach(var hook in hooks)if(hook!=IntPtr.Zero)WindowApi.UnhookWinEvent(hook);
   if(prompt!=null){prompt.Close();}dispatch.Dispose();base.Dispose(disposing);
  }
 }

 static class WindowApi {
  public delegate bool EnumCallback(IntPtr window,IntPtr param);
  public delegate void EventCallback(IntPtr hook,uint kind,IntPtr window,int obj,int child,uint thread,uint time);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumCallback callback,IntPtr param);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr window,uint flags);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr window,int command);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern bool SetProp(IntPtr window,string name,IntPtr value);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetProp(IntPtr window,string name);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr RemoveProp(IntPtr window,string name);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window,uint message,IntPtr w,IntPtr l);
  [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SetWinEventHook(uint min,uint max,IntPtr module,EventCallback callback,uint pid,uint tid,uint flags);
  [DllImport("user32.dll")] public static extern bool UnhookWinEvent(IntPtr hook);
 }

 // The SYSTEM service owns process handles and restarts a session agent if needed.
 // Agents run as the logged-on user, not SYSTEM; their process object is SYSTEM-owned.
 sealed class GuardSupervisor : IDisposable {
  readonly Dictionary<int,IntPtr> agents=new Dictionary<int,IntPtr>();
  readonly ManualResetEvent stop=new ManualResetEvent(false);
  Thread worker;
  public void Start(){worker=new Thread(Run){IsBackground=true};worker.Start();}
  public bool HasAgent(int session){lock(agents){IntPtr handle;return agents.TryGetValue(session,out handle)&&SessionApi.WaitForSingleObject(handle,0)==258;}}
  void Run(){do{
   try{
    lock(agents)foreach(var session in SessionApi.Sessions()){
     IntPtr handle;
     if(agents.TryGetValue(session,out handle)){
      if(SessionApi.WaitForSingleObject(handle,0)==258)continue;
      Native.CloseHandle(handle);agents.Remove(session);
     }
     try{agents[session]=SessionApi.StartAgent(session);}
     catch(Exception ex){Log("Session "+session+": "+ex.Message);}
    }
   }catch(Exception ex){Log(ex.Message);}
  }while(!stop.WaitOne(1000));}
  static void Log(string message){try{File.WriteAllText(Path.Combine(Store.Root,"guard-error.txt"),DateTime.UtcNow.ToString("O")+" "+message);}catch{}}
  public void Dispose(){stop.Set();if(worker!=null)worker.Join(5000);IntPtr[] handles;lock(agents){handles=agents.Values.ToArray();agents.Clear();}foreach(var handle in handles){if(SessionApi.WaitForSingleObject(handle,3000)==258)SessionApi.TerminateProcess(handle,0);Native.CloseHandle(handle);}stop.Dispose();}
 }

 static class SessionApi {
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  public static bool CanTerminate(int pid){IntPtr handle=OpenProcess(1,false,pid);if(handle==IntPtr.Zero)return false;Native.CloseHandle(handle);return true;}
  [StructLayout(LayoutKind.Sequential)] struct Session {public int Id;public IntPtr Station;public int State;}
  [StructLayout(LayoutKind.Sequential)] struct Security {public int Size;public IntPtr Descriptor;public int Inherit;}
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public int cb;public string reserved,desktop,title;public int x,y,xSize,ySize,xChars,yChars,fill,flags;public short show,reserved2;public IntPtr reservedPtr,input,output,error;}
  [StructLayout(LayoutKind.Sequential)] struct Info {public IntPtr process,thread;public uint pid,tid;}
  [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSEnumerateSessions(IntPtr server,int reserved,int version,out IntPtr data,out int count);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr data);
  [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQueryUserToken(uint session,out IntPtr token);
  [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr env,IntPtr token,bool inherit);
  [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr env);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text,uint revision,out IntPtr descriptor,IntPtr size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessAsUser(IntPtr token,string app,StringBuilder command,ref Security process,ref Security thread,bool inherit,uint flags,IntPtr env,string directory,ref Startup startup,out Info info);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr ptr);
  [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr handle,uint ms);
  [DllImport("kernel32.dll")] public static extern bool TerminateProcess(IntPtr process,uint exitCode);
  public static IEnumerable<int> Sessions(){
   IntPtr data;int count;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out data,out count))throw new Win32Exception();
   var result=new List<int>();try{for(int i=0;i<count;i++){var s=(Session)Marshal.PtrToStructure(IntPtr.Add(data,i*Marshal.SizeOf(typeof(Session))),typeof(Session));if(s.Id!=0&&(s.State==0||s.State==1||s.State==4))result.Add(s.Id);}}finally{WTSFreeMemory(data);}return result;
  }
  public static IntPtr StartAgent(int session){
   IntPtr token;if(!WTSQueryUserToken((uint)session,out token))throw new Win32Exception();
   IntPtr env=IntPtr.Zero,descriptor=IntPtr.Zero;
   try{
    if(!CreateEnvironmentBlock(out env,token,false))throw new Win32Exception();
    // Ordinary Task Manager can query but cannot terminate or rewrite the DACL.
    // Elevated administrators intentionally retain full recovery access.
    if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00101000;;;AU)",1,out descriptor,IntPtr.Zero))throw new Win32Exception();
    var security=new Security{Size=Marshal.SizeOf(typeof(Security)),Descriptor=descriptor};
    var startup=new Startup{cb=Marshal.SizeOf(typeof(Startup)),desktop="winsta0\\default"};Info info;
    string command=Native.Quote(Intercept.GatePath)+" --watch "+Process.GetCurrentProcess().Id+(Intercept.TestPipe==null?"":" "+Intercept.TestPipe);
    if(!CreateProcessAsUser(token,Intercept.GatePath,new StringBuilder(command),ref security,ref security,false,0x400,env,Path.GetDirectoryName(Intercept.GatePath),ref startup,out info))throw new Win32Exception();
    Native.CloseHandle(info.thread);return info.process;
   }finally{if(descriptor!=IntPtr.Zero)LocalFree(descriptor);if(env!=IntPtr.Zero)DestroyEnvironmentBlock(env);Native.CloseHandle(token);}
  }
 }
}
