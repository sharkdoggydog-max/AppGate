using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace AppGateServiceEdition {
 static class Tests {
  [StructLayout(LayoutKind.Sequential)] struct SidEntry {public IntPtr Sid;public uint Attributes;}
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token,uint flags,uint count,ref SidEntry disable,uint privileges,IntPtr delete,uint restrictCount,IntPtr restrict,out IntPtr result);
  static bool RestrictedCanTerminate(int pid){
   var sid=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);byte[] bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);IntPtr memory=Marshal.AllocHGlobal(bytes.Length),restricted=IntPtr.Zero;
   try{Marshal.Copy(bytes,0,memory,bytes.Length);var entry=new SidEntry{Sid=memory};using(var identity=WindowsIdentity.GetCurrent()){
    if(!CreateRestrictedToken(identity.Token,1,1,ref entry,0,IntPtr.Zero,0,IntPtr.Zero,out restricted))throw new System.ComponentModel.Win32Exception();
    using(var impersonation=WindowsIdentity.Impersonate(restricted))return SessionApi.CanTerminate(pid);
   }}finally{if(restricted!=IntPtr.Zero)Native.CloseHandle(restricted);Marshal.FreeHGlobal(memory);}
  }
  static int FindAgent(int servicePid,int session){
   using(var search=new System.Management.ManagementObjectSearcher("SELECT ProcessId,ExecutablePath,CommandLine,SessionId FROM Win32_Process WHERE Name='AppGateService.exe'"))using(var results=search.Get())foreach(System.Management.ManagementObject row in results)using(row){
    string command=row["CommandLine"] as string;
    if(Convert.ToInt32(row["SessionId"])==session&&string.Equals(row["ExecutablePath"] as string,Application.ExecutablePath,StringComparison.OrdinalIgnoreCase)&&command!=null&&command.Contains(" --watch "+servicePid+" "+Client.PipeName))return Convert.ToInt32(row["ProcessId"]);
   }return 0;
  }
  public static int Supervisor(){
   progress=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"supervisor-test-result.txt");File.WriteAllText(progress,"SYSTEM supervisor regression\r\n");
   string token=Guid.NewGuid().ToString("N"),serviceName="AppGateTest_"+Guid.NewGuid().ToString("N");bool created=false;
   try{
    Assert(Setup.Admin,"test is elevated");Store.Root=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"supervisor-test-"+token);Client.PipeName="AppGateTest."+token;Intercept.GatePath=Application.ExecutablePath;Intercept.TestPipe=Client.PipeName;
    var settings=new Settings();Passwords.Set(settings,"Supervisor-test-only-129!");Store.Save(settings);
    string bin=Native.Quote(Application.ExecutablePath)+" --test-window-service "+serviceName+" "+Native.Quote(Store.Root)+" "+Client.PipeName+" "+Native.Quote(Application.ExecutablePath);
    Setup.Sc("create "+serviceName+" binPath= "+Native.Quote(bin)+" start= demand",true);created=true;Setup.Sc("start "+serviceName,true);
    using(var service=new ServiceController(serviceName))service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(15));
    Assert(Client.Send(new Request{Command="watch"}).Ok,"window-mode SYSTEM backend responds");int backend=Client.LastServerPid,session=Process.GetCurrentProcess().SessionId,agent=0;
    for(int i=0;i<20&&agent==0;i++){Thread.Sleep(500);agent=FindAgent(backend,session);}
    Assert(agent!=0,"service starts guard in logged-on user session");
    File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"supervisor-agent-pid.txt"),agent.ToString());
    Thread.Sleep(3000);string access=File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"guard-access-"+Client.PipeName+".txt"));File.AppendAllText(progress,"Actual session token: "+access+"\r\n");Assert(!RestrictedCanTerminate(agent),"token without admin group and debug privileges cannot terminate guard");
    Assert(FindAgent(backend,session)==agent,"guard stays alive and does not crash at startup");
    using(var process=Process.GetProcessById(agent)){Assert(string.Equals(Native.ProcessPath(agent),Application.ExecutablePath,StringComparison.OrdinalIgnoreCase),"verify exact test agent before forced termination");process.Kill();process.WaitForExit(5000);}
    int replacement=0;for(int i=0;i<20;i++){Thread.Sleep(500);replacement=FindAgent(backend,session);if(replacement!=0&&replacement!=agent)break;}
    Assert(replacement!=0&&replacement!=agent,"supervisor replaces forcibly terminated guard");
    Setup.Sc("stop "+serviceName,true);using(var service=new ServiceController(serviceName))service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));
    Assert(FindAgent(backend,session)==0,"service stop removes session guard");File.AppendAllText(progress,"ALL PASS\r\n");return 0;
   }catch(Exception ex){File.AppendAllText(progress,"FAIL: "+ex+"\r\n");return 1;}
   finally{if(created){try{Setup.Sc("stop "+serviceName,false);using(var service=new ServiceController(serviceName))service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));Setup.Sc("delete "+serviceName,true);}catch(Exception ex){File.AppendAllText(progress,"CLEANUP ERROR: "+serviceName+" "+ex.Message);}}}
  }
  static System.Collections.Generic.IEnumerable<Control> Children(Control root){foreach(Control c in root.Controls){yield return c;foreach(var child in Children(c))yield return child;}}
  public static int Windows(){
   progress=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"window-test-result.txt");File.WriteAllText(progress,"Real window guard regression\r\n");
   string dir=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"window-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
   string exe=Path.Combine(dir,"AppGateProbe_"+Guid.NewGuid().ToString("N")+".exe"),marker=Path.Combine(dir,"window.txt");File.Copy(Application.ExecutablePath,exe);
   var config=new Settings();Passwords.Set(config,"Window-test-password-321!");config.Rules.Add(new Rule{Exe=Path.GetFileName(exe),Name="Test",Enabled=true});
   Process probe=null;int stage=0;DateTime started=DateTime.UtcNow,advance=started;bool success=false;IntPtr window=IntPtr.Zero;
   Client.PipeName="AppGateTest."+Guid.NewGuid().ToString("N");
   using(var engine=new Engine(config))using(var guard=new WindowGuard())using(var timer=new System.Windows.Forms.Timer{Interval=100}){
    string sid=WindowsIdentity.GetCurrent().User.Value;int session=Process.GetCurrentProcess().SessionId;
    engine.Start();
    guard.Send=q=>engine.Handle(q,sid,session);
    timer.Tick+=(s,e)=>{try{
     if((DateTime.UtcNow-started).TotalSeconds>90)throw new Exception("Timed out at stage "+stage);
     if(stage==0){probe=Process.Start(new ProcessStartInfo(exe,"--window-probe "+Native.Quote(marker)){UseShellExecute=false});stage=1;}
     else if(stage==1&&File.Exists(marker)&&guard.ActivePrompt!=null){window=new IntPtr(long.Parse(File.ReadAllText(marker)));if(WindowApi.IsWindowVisible(window))return;Assert(true,"ordinary exe launch produces password dialog and hidden target");var d=guard.ActivePrompt;Children(d).OfType<TextBox>().First().Text="wrong";Children(d).OfType<Button>().First(b=>b.Text=="Подтвердить").PerformClick();stage=2;}
     else if(stage==2&&Children(guard.ActivePrompt).OfType<Button>().First(b=>b.Text=="Подтвердить").Enabled){Assert(!WindowApi.IsWindowVisible(window)&&Children(guard.ActivePrompt).OfType<Label>().Any(l=>l.Text.StartsWith("Неверный")),"wrong password leaves target hidden");var d=guard.ActivePrompt;Children(d).OfType<TextBox>().First().Text="Window-test-password-321!";Children(d).OfType<Button>().First(b=>b.Text=="Подтвердить").PerformClick();stage=3;}
     else if(stage==3&&WindowApi.IsWindowVisible(window)){Assert(guard.ActivePrompt==null,"correct password restores same window without relaunch");Assert(!probe.HasExited,"original process remains alive");advance=DateTime.UtcNow;stage=4;}
     else if(stage==4&&(DateTime.UtcNow-advance).TotalSeconds>1){Assert(WindowApi.IsWindowVisible(window)&&guard.ActivePrompt==null,"authorized window remains visible across polling");probe.CloseMainWindow();stage=5;}
     else if(stage==5&&probe.HasExited){probe.Dispose();probe=null;File.Delete(marker);advance=DateTime.UtcNow;stage=6;}
     else if(stage==6&&(DateTime.UtcNow-advance).TotalSeconds>3){probe=Process.Start(new ProcessStartInfo(exe,"--window-probe "+Native.Quote(marker)){UseShellExecute=false});stage=7;}
     else if(stage==7&&File.Exists(marker)&&guard.ActivePrompt!=null){window=new IntPtr(long.Parse(File.ReadAllText(marker)));if(WindowApi.IsWindowVisible(window))return;Assert(true,"new launch after closing requires password again");Children(guard.ActivePrompt).OfType<Button>().First(b=>b.Text=="Отмена").PerformClick();stage=8;}
     else if(stage==8&&probe.HasExited){Assert(true,"cancel closes disposable target without showing it");probe.Dispose();File.Delete(marker);probe=Process.Start(new ProcessStartInfo(exe,"--window-probe "+Native.Quote(marker)){UseShellExecute=false});stage=9;}
     else if(stage==9&&File.Exists(marker)&&guard.ActivePrompt!=null){window=new IntPtr(long.Parse(File.ReadAllText(marker)));config.Rules[0].Enabled=false;stage=10;}
     else if(stage==10&&WindowApi.IsWindowVisible(window)&&guard.ActivePrompt==null){Assert(true,"disabling rule restores hidden window");success=true;timer.Stop();guard.ExitThread();}
    }catch(Exception ex){File.AppendAllText(progress,"FAIL: "+ex+"\r\n");timer.Stop();guard.ExitThread();}};
    timer.Start();try{Application.Run(guard);}finally{if(probe!=null){if(!probe.HasExited){probe.Kill();probe.WaitForExit(3000);}probe.Dispose();}}
   }
   if(success){File.AppendAllText(progress,"ALL PASS\r\n");return 0;}return 1;
  }
  public static int Auth(){
   progress=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"auth-test-result.txt");File.WriteAllText(progress,"Password regression tests\r\n");Store.Root=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"auth-test-"+Guid.NewGuid().ToString("N"));
   try{var cfg=new Settings();Passwords.Set(cfg,"Old-password-123");Store.Save(cfg);using(var engine=new Engine(cfg)){
    var now=DateTime.UtcNow;engine.Now=()=>now;string sid="test-user";
    for(int i=0;i<5;i++)Assert(!engine.Handle(new Request{Command="auth",Password="wrong"},sid,1).Ok,"wrong password rejected");
    var blocked=engine.Handle(new Request{Command="auth",Password="Old-password-123"},sid,1);Assert(!blocked.Ok&&blocked.RetryAfterSeconds==30,"cooldown is explicit even for correct password");now=now.AddSeconds(31);
    var wrong=engine.Handle(new Request{Command="auth",Password="wrong"},sid,1);Assert(!wrong.Ok&&wrong.RetryAfterSeconds==0,"counter resets when cooldown expires");
    Assert(!engine.Handle(new Request{Command="password",Password="wrong",Value="New-password-456"},sid,1).Ok,"old password required for change");
    Assert(engine.Handle(new Request{Command="password",Password="Old-password-123",Value="New-password-456"},sid,1).Ok,"password change accepted");
    Assert(!engine.Handle(new Request{Command="auth",Password="Old-password-123"},sid,1).Ok,"old password no longer accepted");
    Assert(engine.Handle(new Request{Command="auth",Password="New-password-456"},sid,1).Ok,"new password immediately accepted");
    using(var loaded=new Engine(Store.Load()))Assert(loaded.Handle(new Request{Command="auth",Password="New-password-456"},sid,1).Ok,"new password survives reload");
    string validRoot=Store.Root;string occupied=Path.Combine(validRoot,"not-directory");File.WriteAllText(occupied,"test");Store.Root=occupied;bool failed=false;try{engine.Handle(new Request{Command="password",Password="New-password-456",Value="Unsaved-password-789"},sid,1);}catch(IOException){failed=true;}finally{Store.Root=validRoot;}Assert(failed,"storage error surfaced");Assert(engine.Handle(new Request{Command="auth",Password="New-password-456"},sid,1).Ok,"failed save preserves active password");
   }File.AppendAllText(progress,"ALL PASS\r\n");return 0;}catch(Exception ex){File.AppendAllText(progress,"FAIL: "+ex);return 1;}
  }
  static string progress;
  static void Assert(bool ok,string name){File.AppendAllText(progress,(ok?"PASS: ":"FAIL: ")+name+Environment.NewLine);if(!ok)throw new Exception(name);}
  static void Wait(int pid){try{using(var p=Process.GetProcessById(pid))if(!p.WaitForExit(8000)){p.Kill();throw new Exception("Probe did not exit");}}catch(ArgumentException){}}
  static int Start(string exe,string marker){using(var p=Process.Start(new ProcessStartInfo(exe,"--probe "+Native.Quote(marker)){UseShellExecute=false,CreateNoWindow=true})){if(!p.WaitForExit(12000)){p.Kill();throw new Exception("Gateway timed out");}return p.ExitCode;}}
  public static int Run(){
   string result=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"integration-result.txt");string token=Guid.NewGuid().ToString("N");string dir=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-"+token);string exe=Path.Combine(dir,"AppGateProbe_"+token+".exe");string marker=Path.Combine(dir,"marker with spaces.txt");Engine engine=null;bool registered=false;string serviceName="AppGateTest_"+token;bool serviceCreated=false;
   try{
    progress=result;File.WriteAllText(progress,"Running integration checks\r\n");
    Assert(Setup.Admin,"Run integration test elevated: a temporary IFEO rule for the uniquely named probe is required.");Directory.CreateDirectory(dir);File.Copy(Application.ExecutablePath,exe);Store.Root=Path.Combine(dir,"data");Client.PipeName="AppGateTest."+token;Intercept.TestPipe=Client.PipeName;Intercept.GatePath=Application.ExecutablePath;
    var cfg=new Settings();Passwords.Set(cfg,"AppGate-test-password-397!");Assert(Passwords.Check(cfg,"AppGate-test-password-397!"),"password accepted");Assert(!Passwords.Check(cfg,"bad"),"wrong password rejected");Store.Save(cfg);Assert(Passwords.Check(Store.Load(),"AppGate-test-password-397!"),"DPAPI and config roundtrip");
    bool blocked=false;try{Intercept.Validate("explorer.exe");}catch(ArgumentException){blocked=true;}Assert(blocked,"system executable rejected");blocked=false;try{Intercept.Validate("..\\evil.exe");}catch(ArgumentException){blocked=true;}Assert(blocked,"registry path traversal rejected");
    Wait(Native.Launch(new[]{exe,"--probe",marker}));Assert(File.Exists(marker),"native debug launch + detach");File.Delete(marker);
    cfg.Rules.Add(new Rule{Name="Disposable probe",Exe=Path.GetFileName(exe),Enabled=true});Store.Save(cfg);engine=new Engine(cfg);engine.Start();Thread.Sleep(300);
    Intercept.Set(Path.GetFileName(exe),true);registered=true;
    Assert(Start(exe,marker)==2&&!File.Exists(marker),"IFEO must intercept before first instruction without password");
    var bad=Client.Send(new Request{Command="allow",Value=exe,Password="bad"});Assert(!bad.Ok,"server rejects wrong password");Assert(Start(exe,marker)==2&&!File.Exists(marker),"denied after wrong password");
    Assert(Client.Send(new Request{Command="allow",Value=exe,Password="AppGate-test-password-397!"}).Ok,"server grants authorized lease");
    Assert(!Client.Send(new Request{Command="open",Value=exe,Password="bad"}).Ok,"explicit shortcut requires password even with active lease");
    Assert(!Client.Send(new Request{Command="gate-entry",Value=exe,Name="verified-child"}).Ok,"normal shortcut requires password despite live lease and forged child flag");
    Assert(!Client.Send(new Request{Command="allow-entry",Value=exe,Password="bad"}).Ok,"normal shortcut rejects wrong password despite live lease");
    Assert(Client.Send(new Request{Command="allow-entry",Value=exe,Password="AppGate-test-password-397!"}).Ok,"normal shortcut accepts correct password");
    Assert(Start(exe,marker)==0,"authorized gateway exits successfully");Thread.Sleep(1500);Assert(File.Exists(marker),"authorized target executes");File.Delete(marker);
    string sid=WindowsIdentity.GetCurrent().User.Value;Assert(!engine.Handle(new Request{Command="gate",Value=exe},sid+"-other",Process.GetCurrentProcess().SessionId).Ok,"lease isolated by SID");Assert(!engine.Handle(new Request{Command="gate",Value=exe},sid,Process.GetCurrentProcess().SessionId+100).Ok,"lease isolated by session");
    Thread.Sleep(2500);Assert(Start(exe,marker)==2&&!File.Exists(marker),"lease expires after app closes");
    Assert(Client.Send(new Request{Command="toggle",Value=Path.GetFileName(exe),Password="AppGate-test-password-397!"}).Ok,"disable disposable rule for shortcut setup test");
    Assert(!Client.Send(new Request{Command="open",Value=exe,Password="bad"}).Ok,"bad password cannot enable or launch disabled rule");Assert(!cfg.Rules[0].Enabled,"failed shortcut leaves disabled rule unchanged");
    Assert(Client.Send(new Request{Command="open",Value=exe,Password="AppGate-test-password-397!"}).Ok,"shortcut enables protection and grants lease in one step");Assert(cfg.Rules[0].Enabled&&Intercept.IsOwned(Path.GetFileName(exe)),"shortcut preserves system protection");
    Assert(Start(exe,marker)==0,"launch after explicit shortcut authentication");Thread.Sleep(1500);Assert(File.Exists(marker),"shortcut target starts");File.Delete(marker);
    engine.Dispose();engine=null;Assert(Start(exe,marker)==3&&!File.Exists(marker),"stopped backend fails closed without running target");
    string bin=Native.Quote(Application.ExecutablePath)+" --test-service "+serviceName+" "+Native.Quote(Store.Root)+" "+Client.PipeName+" "+Native.Quote(Application.ExecutablePath)+" test";
    Setup.Sc("create "+serviceName+" binPath= "+Native.Quote(bin)+" start= demand",true);serviceCreated=true;Setup.Sc("failure "+serviceName+" reset= 86400 actions= restart/1000",true);Setup.Sc("start "+serviceName,true);using(var svc=new ServiceController(serviceName))svc.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(15));
    Assert(Client.Send(new Request{Command="list"}).Ok,"real Windows service responds");int servicePid=Client.LastServerPid;using(var p=Process.GetProcessById(servicePid)){Assert(p.SessionId==0,"backend runs in service session zero");Assert(string.Equals(Native.ProcessPath(p.Id),Application.ExecutablePath,StringComparison.OrdinalIgnoreCase),"verify disposable service binary before termination");p.Kill();p.WaitForExit(5000);}
    bool recovered=false;for(int i=0;i<15;i++){Thread.Sleep(500);try{if(Client.Send(new Request{Command="list"}).Ok&&Client.LastServerPid!=servicePid){recovered=true;break;}}catch{}}Assert(recovered,"Windows restarts backend after task termination");
    Assert(Start(exe,marker)==2&&!File.Exists(marker),"service restart does not grant access");Assert(Client.Send(new Request{Command="allow",Value=exe,Password="AppGate-test-password-397!"}).Ok,"real service authorizes");Assert(Start(exe,marker)==0,"real service authorized gateway");Thread.Sleep(1500);Assert(File.Exists(marker),"real service authorized target runs");
    File.WriteAllText(result,"PASS: PBKDF2; wrong password; DPAPI config; protected executable validation; native launch/detach; real IFEO denies before target starts; IPC rejects wrong password; authorized launch; SID/session isolation; lease expiry; shortcut always requires password even during active lease; shortcut enables disabled rule only after valid password and launches target; unavailable backend fails closed; actual Windows service in session 0; automatic service restart after task termination; authorized launch via actual service.\r\nOS: "+Environment.OSVersion+"\r\nMicrosoft Store activation and Windows 11 are not tested.\r\n");return 0;
   }catch(Exception ex){File.AppendAllText(result,"FAIL: "+ex);return 1;}
   finally{if(engine!=null)engine.Dispose();if(serviceCreated){try{Setup.Sc("stop "+serviceName,false);using(var s=new ServiceController(serviceName))s.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));Setup.Sc("delete "+serviceName,true);}catch(Exception ex){File.AppendAllText(result,"\r\nSERVICE CLEANUP ERROR: "+serviceName+" "+ex.Message);}}if(registered){try{Intercept.Set(Path.GetFileName(exe),false);using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)){string key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+Path.GetFileName(exe);bool empty;using(var k=root.OpenSubKey(key))empty=k!=null&&k.ValueCount==0&&k.SubKeyCount==0;if(empty)root.DeleteSubKey(key);}}catch(Exception ex){File.AppendAllText(result,"\r\nCLEANUP ERROR: "+ex.Message+". Temporary rule: "+Path.GetFileName(exe));}}}
  }
 }
}
