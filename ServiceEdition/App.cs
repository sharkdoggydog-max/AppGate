using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace AppGateServiceEdition {
 class GateService : ServiceBase {
  Engine engine;
  GuardSupervisor supervisor;
  bool forceWindowMode;
  public GateService(){ServiceName="AppGateService";CanStop=true;AutoLog=true;}
  public GateService(string name):this(){ServiceName=name;}
  public GateService(string name,bool windowMode):this(name){forceWindowMode=windowMode;}
  protected override void OnStart(string[] args){Intercept.WindowMode=forceWindowMode||ServiceName=="AppGateService";if(Intercept.WindowMode)Intercept.Recover();var s=Store.Load();foreach(var r in s.Rules.Where(x=>x.Enabled))Intercept.Set(r.Exe,true);engine=new Engine(s);if(Intercept.WindowMode){supervisor=new GuardSupervisor();engine.GuardAvailable=supervisor.HasAgent;}engine.Start();if(supervisor!=null)supervisor.Start();}
  protected override void OnStop(){if(engine!=null)engine.PrepareStop();if(supervisor!=null)supervisor.Dispose();if(engine!=null)engine.Dispose();}
 }
 class PasswordDialog : Form {
  readonly TextBox input=new TextBox{UseSystemPasswordChar=true,Width=360};readonly TextBox confirmation=new TextBox{UseSystemPasswordChar=true,Width=360};
  public string Password{get{return input.Text;}}
  internal event Action Verified;
  public PasswordDialog(string title,bool create,Func<string,Reply> check,string label=null){
   Text=title;Font=new Font("Segoe UI",10);ClientSize=new Size(450,create?330:290);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;MinimizeBox=false;StartPosition=FormStartPosition.CenterScreen;TopMost=true;ShowInTaskbar=true;
   var panel=new FlowLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(24),FlowDirection=FlowDirection.TopDown,WrapContents=false};Controls.Add(panel);
   panel.Controls.Add(new Label{Text=label??(create?"Новый пароль AppGate (10–256 символов)":"Текущий пароль AppGate"),AutoSize=true});panel.Controls.Add(input);
   if(create){panel.Controls.Add(new Label{Text="Повторите пароль",AutoSize=true});panel.Controls.Add(confirmation);}
   var show=new CheckBox{Text="Показать пароль",AutoSize=true};show.CheckedChanged+=(s,e)=>{input.UseSystemPasswordChar=!show.Checked;confirmation.UseSystemPasswordChar=!show.Checked;};panel.Controls.Add(show);
   var keyboard=new Label{AutoSize=true};panel.Controls.Add(keyboard);
   var line=new FlowLayoutPanel{Width=370,Height=40};var ok=new Button{Text=create?"Создать":"Подтвердить",Width=140,Height=32};var cancel=new Button{Text="Отмена",Width=100,Height=32,DialogResult=DialogResult.Cancel};line.Controls.Add(ok);line.Controls.Add(cancel);panel.Controls.Add(line);
   var error=new Label{AutoSize=true,MaximumSize=new Size(360,0),ForeColor=Color.DarkRed};panel.Controls.Add(error);AcceptButton=ok;CancelButton=cancel;
   DateTime retry=DateTime.MinValue;var clock=new System.Windows.Forms.Timer{Interval=250};clock.Tick+=(s,e)=>{keyboard.Text="Раскладка: "+InputLanguage.CurrentInputLanguage.Culture.TwoLetterISOLanguageName.ToUpperInvariant()+(Control.IsKeyLocked(Keys.CapsLock)?"   CAPS LOCK включён":"");if(retry!=DateTime.MinValue){int remain=(int)Math.Ceiling((retry-DateTime.UtcNow).TotalSeconds);if(remain<=0){retry=DateTime.MinValue;ok.Enabled=true;error.Text="Можно повторить ввод пароля.";}else error.Text="Слишком много ошибок. Повторите через "+remain+" сек.";}};clock.Start();FormClosed+=(s,e)=>clock.Dispose();
   cancel.Click+=(s,e)=>{DialogResult=DialogResult.Cancel;Close();};
   Shown+=(s,e)=>{Activate();BringToFront();input.Select();Native.SetForegroundWindow(Handle);};
   bool busy=false;FormClosing+=(s,e)=>{if(busy)e.Cancel=true;};
   ok.Click+=async(s,e)=>{ok.Enabled=false;cancel.Enabled=false;input.Enabled=false;confirmation.Enabled=false;busy=true;try{
    if(create){if(input.Text.Length<10||input.Text.Length>256||input.Text!=confirmation.Text){error.Text="От 10 до 256 символов. Пароли должны совпадать.";return;}}
    else{string password=input.Text;var r=await System.Threading.Tasks.Task.Run(()=>check(password));if(!r.Ok){error.Text=r.Message;if(r.RetryAfterSeconds>0)retry=DateTime.UtcNow.AddSeconds(r.RetryAfterSeconds);return;}}
    if(create&&check!=null){string password=input.Text;var r=await System.Threading.Tasks.Task.Run(()=>check(password));if(!r.Ok){error.Text=r.Message;return;}}
    busy=false;if(Verified!=null)Verified();DialogResult=DialogResult.OK;Close();
   }catch{if(!IsDisposed)error.Text="Служба недоступна. Изменение не подтверждено.";}finally{busy=false;if(!IsDisposed){ok.Enabled=retry==DateTime.MinValue;cancel.Enabled=true;input.Enabled=true;confirmation.Enabled=true;}}};
  }
 }
 class ControlWindow : Form {
  readonly ListBox list=new ListBox{Dock=DockStyle.Fill};readonly Label status=new Label{Dock=DockStyle.Bottom,Height=65,Padding=new Padding(16)};
  public ControlWindow(){
   Text="AppGate 3 — защита окон приложений";Font=new Font("Segoe UI",10);Size=new Size(780,510);MinimumSize=new Size(740,490);StartPosition=FormStartPosition.CenterScreen;
   var heading=new Label{Text="AppGate 3",Dock=DockStyle.Top,Height=65,Padding=new Padding(16,10,0,0),Font=new Font("Segoe UI",24,FontStyle.Bold)};
   var intro=new Label{Text="Защита обслуживается службой Windows для всех пользователей.\nМожно закрыть это окно — правила продолжат работать.",Dock=DockStyle.Top,Height=65,Padding=new Padding(16,0,0,0)};
   var actions=new FlowLayoutPanel{Dock=DockStyle.Bottom,Height=125,Padding=new Padding(12)};
   Controls.Add(list);Controls.Add(intro);Controls.Add(heading);Controls.Add(actions);Controls.Add(status);
   Button(actions,"Добавить приложение",()=>{using(var d=new OpenFileDialog{Filter="Приложения (*.exe)|*.exe"})if(d.ShowDialog()==DialogResult.OK)Run("add",d.FileName);});
   Button(actions,"Включить / выключить",()=>{var r=list.SelectedItem as Rule;if(r==null)return;
    if(!r.Enabled){if(MessageBox.Show("Окна всех приложений с именем "+r.Exe+" будут скрываться до ввода пароля для каждого пользователя Windows, включая уже открытые окна. Обычные ярлыки менять не нужно.\n\nЭто защита доступа к окнам: процессы могут работать в фоне до ввода пароля. Окна с более высокими правами, чем у защитника, не поддерживаются. Администратор может обойти защиту.\n\nВключить?","Включение защиты",MessageBoxButtons.YesNo,MessageBoxIcon.Information)!=DialogResult.Yes)return;}
    Run("toggle",r.Exe);
   });
   Button(actions,"Удалить правило",()=>{var r=list.SelectedItem as Rule;if(r!=null)Run("remove",r.Exe);});
   Button(actions,"Сменить пароль",()=>{
    string current=null;try{using(var old=new PasswordDialog("Шаг 1 из 2 — текущий пароль",false,p=>Client.Send(new Request{Command="auth",Password=p}),"Введите СТАРЫЙ действующий пароль")){if(old.ShowDialog()!=DialogResult.OK)return;current=old.Password;}
     using(var next=new PasswordDialog("Шаг 2 из 2 — новый пароль",true,p=>Client.Send(new Request{Command="password",Password=current,Value=p})))if(next.ShowDialog()==DialogResult.OK)MessageBox.Show("Новый пароль сохранён службой. Теперь используйте его для всех действий AppGate.","Пароль изменён",MessageBoxButtons.OK,MessageBoxIcon.Information);
    }finally{current=null;}
   });
   Button(actions,"Обновить",RefreshRules);
   Button(actions,"Удалить AppGate",()=>Setup.Elevate("--uninstall"));
   Button(actions,"Закрыть окно",Close);
   Shown+=(s,e)=>RefreshRules();
  }
  void Button(Control c,string text,Action action){var b=new Button{Text=text,AutoSize=true,Height=34};c.Controls.Add(b);b.Click+=(s,e)=>{try{action();}catch(Exception ex){MessageBox.Show(ex.Message,"AppGate");}};}
  void Run(string command,string value){using(var d=new PasswordDialog("Подтвердите изменение",false,p=>Client.Send(new Request{Command=command,Value=value,Password=p})))d.ShowDialog();RefreshRules();}
  void RefreshRules(){try{var result=Client.Send(new Request{Command="list"});string selected=(list.SelectedItem as Rule)==null?null:((Rule)list.SelectedItem).Exe;list.Items.Clear();foreach(var r in result.Rules)list.Items.Add(r);foreach(Rule r in list.Items)if(r.Exe==selected){list.SelectedItem=r;break;}status.ForeColor=result.GuardReady?Color.DarkGreen:Color.DarkRed;status.Text=!result.WindowMode?"Установлена старая служба. Требуется обновление AppGate.":result.GuardReady?"Служба и защитник сеанса работают. ● Включено   ○ Выключено\nПароль запрашивается снова после закрытия последнего окна приложения.":"Служба работает, но защитник вашего сеанса недоступен. Нажмите «Обновить».";}catch{status.ForeColor=Color.DarkRed;status.Text="Служба недоступна. Защита новых окон не гарантируется.\nЗапустите службу AppGateService или используйте аварийное восстановление из инструкции.";}}
 }
 static class Setup {
  public const string ServiceName="AppGateService";
  const string UninstallKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AppGateService";
  public static bool Admin{get{return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);}}
  public static void Elevate(string arg){Process.Start(new ProcessStartInfo(System.Windows.Forms.Application.ExecutablePath,arg){UseShellExecute=true,Verb="runas"});}
  public static void ArchiveLegacyShortcuts(){
   Type type=Type.GetTypeFromProgID("WScript.Shell");dynamic shell=Activator.CreateInstance(type);
   try{foreach(string folder in new[]{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Environment.GetFolderPath(Environment.SpecialFolder.Programs)}){
    string path=Path.Combine(folder,"Codex — с паролем.lnk");if(!File.Exists(path))continue;bool owned=false;dynamic link=shell.CreateShortcut(path);try{owned=string.Equals((string)link.TargetPath,Intercept.GatePath,StringComparison.OrdinalIgnoreCase)&&(string)link.Arguments=="--open-codex";}finally{System.Runtime.InteropServices.Marshal.FinalReleaseComObject(link);}if(owned){string archive=Path.Combine(Store.Root,"legacy-shortcuts",Guid.NewGuid().ToString("N"));Directory.CreateDirectory(archive);File.Move(path,Path.Combine(archive,Path.GetFileName(path)));}
   }}finally{System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);}
  }
  public static void Update(){
   if(!Admin){using(var p=Process.Start(new ProcessStartInfo(Application.ExecutablePath,"--update"){UseShellExecute=true,Verb="runas"}))p.WaitForExit();return;}
   if(!Installed()){Install();return;}if(string.Equals(Application.ExecutablePath,Intercept.GatePath,StringComparison.OrdinalIgnoreCase))throw new IOException("Запустите обновление из папки новой сборки, а не из Program Files.");
   string backup=Intercept.GatePath+".backup-"+DateTime.UtcNow.ToString("yyyyMMddHHmmss");bool moved=false;
   Sc("stop AppGateService",true);using(var s=new ServiceController(ServiceName))s.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));
   try{File.Move(Intercept.GatePath,backup);moved=true;File.Copy(Application.ExecutablePath,Intercept.GatePath);Sc("start AppGateService",true);using(var s=new ServiceController(ServiceName))s.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(15));
    using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))using(var k=root.OpenSubKey(UninstallKey,true))if(k!=null){k.SetValue("DisplayVersion","3.0.0");k.SetValue("DisplayName","AppGate 3 — защита окон приложений");}
   }catch{if(moved){Sc("stop AppGateService",false);using(var s=new ServiceController(ServiceName))s.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));if(File.Exists(Intercept.GatePath))File.Move(Intercept.GatePath,Intercept.GatePath+".failed-"+DateTime.UtcNow.Ticks);File.Move(backup,Intercept.GatePath);}Sc("start AppGateService",false);throw;}
   // Window guard observes ordinary launches; no replacement shortcuts.
   ArchiveLegacyShortcuts();
  }
  public static void Sc(string args,bool required){using(var p=Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"sc.exe"),args){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})){string output=p.StandardOutput.ReadToEnd();p.WaitForExit();if(required&&p.ExitCode!=0)throw new IOException("Ошибка настройки службы: "+output);}}
  public static bool Installed(){return ServiceController.GetServices().Any(s=>{using(s)return s.ServiceName==ServiceName;});}
  public static void Install(){
   if(!Admin){Elevate("--install");return;}if(Installed())throw new InvalidOperationException("AppGate уже установлен. Откройте приложение для настройки.");
   if(MessageBox.Show("Будут установлены служба AppGateService с автоматическим запуском и приложение в Program Files. Пароль действует для всех пользователей.\n\nПравило Codex первоначально выключено. Включите его после настройки.\n\nУстановить?","Установка AppGate 3",MessageBoxButtons.YesNo,MessageBoxIcon.Information)!=DialogResult.Yes)return;
   Settings config;if(File.Exists(Store.FileName)){config=Store.Load();using(var d=new PasswordDialog("Пароль существующей установки",false,p=>new Reply{Ok=Passwords.Check(config,p),Message="Неверный пароль"}))if(d.ShowDialog()!=DialogResult.OK)return;}
   else{config=new Settings();using(var d=new PasswordDialog("Создание пароля",true,null)){if(d.ShowDialog()!=DialogResult.OK)return;Passwords.Set(config,d.Password);}config.Rules.Add(new Rule{Name="Codex / ChatGPT",Exe="ChatGPT.exe",Enabled=false});}
   string folder=Path.GetDirectoryName(Intercept.GatePath);Store.Restrict(folder,true);Store.Restrict(Store.Root,false);
   if(!string.Equals(Application.ExecutablePath,Intercept.GatePath,StringComparison.OrdinalIgnoreCase))File.Copy(Application.ExecutablePath,Intercept.GatePath,true);Store.Save(config);
   bool created=false;try{
    Sc("create AppGateService binPath= "+Native.Quote(Native.Quote(Intercept.GatePath)+" --service")+" start= auto DisplayName= \"AppGate — защита приложений\"",true);
    created=true;
    Sc("description AppGateService \"Проверка пароля AppGate. Закрытие интерфейса не отключает правила.\"",true);
    Sc("failure AppGateService reset= 86400 actions= restart/2000/restart/5000/restart/15000",true);
    Sc("start AppGateService",true);using(var service=new ServiceController(ServiceName))service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(15));
    using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))using(var k=root.CreateSubKey(UninstallKey)){k.SetValue("DisplayName","AppGate 3 — защита окон приложений");k.SetValue("DisplayVersion","3.0.0");k.SetValue("Publisher","AppGate (local build)");k.SetValue("InstallLocation",folder);k.SetValue("UninstallString",Native.Quote(Intercept.GatePath)+" --uninstall");k.SetValue("NoModify",1);k.SetValue("NoRepair",1);}
    MessageBox.Show("Установлено. Включите защиту приложения один раз. При новом запуске используйте его обычный ярлык.","AppGate");Process.Start(Intercept.GatePath);
   }catch{if(created){Sc("stop AppGateService",false);Sc("delete AppGateService",false);}throw;}
  }
  public static void Remove(bool recovery){
   if(!Admin){Elevate(recovery?"--recover":"--uninstall");return;}
   if(!recovery){using(var d=new PasswordDialog("Пароль для удаления AppGate",false,p=>Client.Send(new Request{Command="auth",Password=p})))if(d.ShowDialog()!=DialogResult.OK)return;}
   if(MessageBox.Show("Снять все правила AppGate и удалить службу? Установленные файлы и настройки останутся для ручного удаления.",recovery?"Восстановление администратором":"Удаление AppGate",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
   if(Installed()){Sc("stop AppGateService",false);using(var s=new ServiceController(ServiceName))s.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));}
   Intercept.Recover();Sc("delete AppGateService",false);using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64))root.DeleteSubKeyTree(UninstallKey,false);
   if(File.Exists(Store.FileName)){var c=Store.Load();foreach(var r in c.Rules)r.Enabled=false;Store.Save(c);}
   MessageBox.Show("Защита снята, служба удалена. После закрытия окна можно удалить папки Program Files\\AppGateService и ProgramData\\AppGateService.","AppGate");
  }
 }
 static class Program {
  [STAThread] public static int Main(string[] args){
   if(args.Length==5&&args[0]=="--test-window-service"&&args[1].StartsWith("AppGateTest_")&&args[3].StartsWith("AppGateTest.")){Store.Root=args[2];Client.PipeName=args[3];Intercept.TestPipe=args[3];Intercept.GatePath=args[4];ServiceBase.Run(new GateService(args[1],true));return 0;}
   if(args.Length==6&&args[0]=="--test-service"&&args[1].StartsWith("AppGateTest_")&&args[3].StartsWith("AppGateTest.")){Store.Root=args[2];Client.PipeName=args[3];Intercept.TestPipe=args[3];Intercept.GatePath=args[4];ServiceBase.Run(new GateService(args[1]));return 0;}
   if(args.Length>0&&args[0]=="--service"){ServiceBase.Run(new GateService());return 0;}
   Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
   try{
    if((args.Length==2||args.Length==3)&&args[0]=="--watch"){
     Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
     if(args.Length==3){if(!args[2].StartsWith("AppGateTest.")||args[2].IndexOfAny(Path.GetInvalidFileNameChars())>=0)return 4;Client.PipeName=args[2];Intercept.GatePath=Application.ExecutablePath;}
     int parent=int.Parse(args[1]);using(var service=Process.GetProcessById(parent)){if(service.SessionId!=0||!string.Equals(Native.ProcessPath(parent),Intercept.GatePath,StringComparison.OrdinalIgnoreCase))return 4;}
     if(args.Length==3)File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"guard-access-"+Client.PipeName+".txt"),"Admin="+Setup.Admin+";Terminate="+SessionApi.CanTerminate(Process.GetCurrentProcess().Id));
     using(var guard=new WindowGuard{ParentPid=parent})Application.Run(guard);return 0;
    }
    if(args.Length>0&&args[0]=="--diagnose-launch"){
     string report="";try{string exe=Native.CodexPath();report+="Package resolution: OK\r\n";try{var reply=Client.Send(new Request{Command="list"});report+="Service connection: "+reply.Ok+"\r\n";foreach(var r in reply.Rules)report+=r.Exe+" Enabled="+r.Enabled+"\r\n";}catch(Exception error){report+="Service: "+error.GetType().Name+" "+error.Message+"\r\n";}report+=Native.DiagnoseLaunch(exe);}catch(Exception error){report+=error.GetType().Name+" "+error.Message;}File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"launch-diagnosis.txt"),report);return 0;
    }
    if(args.Length>0&&args[0]=="--status"){
     var result=Client.Send(new Request{Command="list"});File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"status.txt"),"Service PID="+Client.LastServerPid+" WindowMode="+result.WindowMode+" GuardReady="+result.GuardReady+"\r\n"+string.Join("\r\n",result.Rules.Select(r=>r.Exe+" Enabled="+r.Enabled)));return 0;
    }
    if(args.Length==2&&args[0]=="--window-inventory"){
     int count=0,visible=0;WindowApi.EnumWindows((w,p)=>{uint pid;WindowApi.GetWindowThreadProcessId(w,out pid);try{using(var process=Process.GetProcessById((int)pid))if(string.Equals(process.ProcessName+".exe",args[1],StringComparison.OrdinalIgnoreCase)){count++;if(WindowApi.IsWindowVisible(w))visible++;}}catch{}return true;},IntPtr.Zero);File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"window-inventory.txt"),args[1]+": top-level windows="+count+"; visible="+visible);return 0;
    }
    if(args.Length>0&&args[0]=="--auth-test")return Tests.Auth();
    if(args.Length>0&&args[0]=="--window-test")return Tests.Windows();
    if(args.Length>0&&args[0]=="--performance-test")return Tests.Performance();
    if(args.Length>0&&args[0]=="--supervisor-test")return Tests.Supervisor();
    if(args.Length==2&&args[0]=="--window-probe"){
     using(var form=new Form{Text="AppGate disposable window",Width=420,Height=220}){form.Shown+=(s,e)=>File.WriteAllText(args[1],form.Handle.ToInt64().ToString());Application.Run(form);}return 0;
    }
    if(args.Length>0&&args[0]=="--resolve-codex"){File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"codex-path.txt"),Native.CodexPath());return 0;}
    if(args.Length>0&&(args[0]=="--make-shortcuts"||args[0]=="--open-codex")){MessageBox.Show("Специальные ярлыки больше не используются. Запустите Codex обычным способом.","AppGate 3");return 0;}
    if(args.Length>0&&args[0]=="--update"){Setup.Update();return 0;}
    if(args.Length>0&&args[0]=="--integration-test")return Tests.Run();
    if(args.Length>0&&args[0]=="--probe"){File.WriteAllText(args[1],"started");Thread.Sleep(700);return 0;}
    if(args.Length>0&&(args[0]=="--gate"||args[0]=="--test-gate")){
     bool test=args[0]=="--test-gate";int skip=test?2:1;if(test){if(args.Length<3||!args[1].StartsWith("AppGateTest."))return 1;Client.PipeName=args[1];}
     string[] target=args.Skip(skip).ToArray();if(target.Length==0)return 1;string exe=Path.GetFileName(target[0]);
     bool created;using(var mutex=new Mutex(false,"Local\\AppGatePrompt-"+exe.ToLowerInvariant(),out created)){
      bool held=false;try{try{held=mutex.WaitOne(60000);}catch(AbandonedMutexException){held=true;}if(!held)return 1;
       var reply=Client.Send(new Request{Command=test?"gate":"gate-entry",Value=target[0]});if(!reply.Ok){if(test)return 2;using(var d=new PasswordDialog("Разблокировать "+exe,false,p=>Client.Send(new Request{Command="allow-entry",Value=target[0],Password=p})))if(d.ShowDialog()!=DialogResult.OK)return 2;}
       Native.Launch(target);return 0;
      }finally{if(held)mutex.ReleaseMutex();}
     }
    }
    if(args.Length>0&&args[0]=="--install"){Setup.Install();return 0;}
    if(args.Length>0&&args[0]=="--uninstall"){Setup.Remove(false);return 0;}
    if(args.Length>0&&args[0]=="--recover"){Setup.Remove(true);return 0;}
    if(!Setup.Installed()){Setup.Install();return 0;}
    Application.Run(new ControlWindow());return 0;
   }catch(Exception ex){if(args.Length>0&&args[0]=="--watch"){try{string folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AppGateService");Directory.CreateDirectory(folder);File.WriteAllText(Path.Combine(folder,"guard-client-error.txt"),DateTime.UtcNow.ToString("O")+" "+ex.GetType().Name+": "+ex.Message);}catch{}return 1;}if(args.Length>0&&args[0]=="--test-gate")return 3;MessageBox.Show("Операция не выполнена: "+ex.Message,"AppGate",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
  }
 }
}
