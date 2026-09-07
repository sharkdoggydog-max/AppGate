using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Xml.Serialization;

namespace AppGate {
 public class Rule {
  public string Name;
  public string Path;
  public bool Enabled;
  public override string ToString() { return (Enabled ? "● " : "○ ") + Name; }
 }
 public class Config { public byte[] Salt; public byte[] Hash; public List<Rule> Rules = new List<Rule>(); }
 static class Secrets {
  public static byte[] Derive(string p, byte[] salt) { using(var k = new Rfc2898DeriveBytes(p, salt, 210000, HashAlgorithmName.SHA256)) return k.GetBytes(32); }
  public static void Set(Config c, string p) { c.Salt = new byte[32]; using(var r = RandomNumberGenerator.Create()) r.GetBytes(c.Salt); c.Hash = Derive(p,c.Salt); }
  public static bool Check(Config c, string p) { var h=Derive(p,c.Salt); int diff=h.Length ^ c.Hash.Length; for(int i=0;i<h.Length && i<c.Hash.Length;i++) diff |= h[i]^c.Hash[i]; return diff==0; }
 }
 static class Storage {
  public static string Folder = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AppGate");
  public static string FileName { get { return System.IO.Path.Combine(Folder,"settings.dat"); } }
  public static byte[] Encode(Config c) { using(var m=new MemoryStream()) { new XmlSerializer(typeof(Config)).Serialize(m,c); return ProtectedData.Protect(m.ToArray(),null,DataProtectionScope.CurrentUser); } }
  public static Config Decode(byte[] b) { using(var m=new MemoryStream(ProtectedData.Unprotect(b,null,DataProtectionScope.CurrentUser))) return (Config)new XmlSerializer(typeof(Config)).Deserialize(m); }
  public static void Save(Config c) { Directory.CreateDirectory(Folder); string t=FileName+".tmp"; File.WriteAllBytes(t,Encode(c)); if(File.Exists(FileName)) File.Replace(t,FileName,null); else File.Move(t,FileName); }
 }
 static class Target {
  public static bool Match(Rule r,string path) {
   if(r.Path=="codex-store") {
    string root=System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WindowsApps")+"\\";
    if(!path.StartsWith(root,StringComparison.OrdinalIgnoreCase)) return false;
    string tail=path.Substring(root.Length); string[] parts=tail.Split('\\');
    return parts.Length==3 && parts[0].StartsWith("OpenAI.Codex_",StringComparison.OrdinalIgnoreCase) && parts[0].EndsWith("_2p2nqsd0c76g0",StringComparison.OrdinalIgnoreCase) && parts[1].Equals("app",StringComparison.OrdinalIgnoreCase) && parts[2].Equals("ChatGPT.exe",StringComparison.OrdinalIgnoreCase);
   }
   return string.Equals(r.Path,path,StringComparison.OrdinalIgnoreCase);
  }
  public static List<Process> Find(Rule r) {
   var found=new List<Process>(); string name=r.Path=="codex-store"?"ChatGPT":System.IO.Path.GetFileNameWithoutExtension(r.Path);
   foreach(var p in Process.GetProcessesByName(name)) {
    try { if(p.Id!=Process.GetCurrentProcess().Id && p.SessionId==Process.GetCurrentProcess().SessionId && Match(r,p.MainModule.FileName)) { found.Add(p); continue; } } catch { }
    p.Dispose();
   } return found;
  }
  public static bool Stop(Rule r) { bool ok=true; foreach(var p in Find(r)) { using(p) { try { p.Kill(); } catch { ok=false; } } } return ok; }
  public static void Launch(Rule r) { if(r.Path=="codex-store") Process.Start(new ProcessStartInfo("explorer.exe","shell:AppsFolder\\OpenAI.Codex_2p2nqsd0c76g0!App") {UseShellExecute=true}); else Process.Start(new ProcessStartInfo(r.Path) {UseShellExecute=true,WorkingDirectory=System.IO.Path.GetDirectoryName(r.Path)}); }
 }
 class PasswordBox : Form {
  public TextBox Input=new TextBox { UseSystemPasswordChar=true, Dock=DockStyle.Fill };
  TextBox confirm=new TextBox {UseSystemPasswordChar=true,Dock=DockStyle.Fill};
  Label message=new Label {AutoSize=true,MaximumSize=new Size(370,0)};
  public PasswordBox(string title,bool setup,Config c) {
   Text=title; ClientSize=new Size(410,setup?245:205); FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false; MinimizeBox=false; StartPosition=FormStartPosition.CenterScreen; TopMost=true;
   var flow=new FlowLayoutPanel {Dock=DockStyle.Fill,Padding=new Padding(20),FlowDirection=FlowDirection.TopDown,WrapContents=false}; Controls.Add(flow);
   flow.Controls.Add(new Label {Text=setup?"Создайте пароль (минимум 8 символов)":"Введите пароль AppGate",AutoSize=true}); Input.Width=365; Input.Dock=DockStyle.None; flow.Controls.Add(Input);
   if(setup) { flow.Controls.Add(new Label {Text="Повторите пароль",AutoSize=true}); confirm.Width=365;confirm.Dock=DockStyle.None;flow.Controls.Add(confirm); }
   var ok=new Button {Text=setup?"Сохранить":"Открыть",Width=120,Height=32}; flow.Controls.Add(ok); flow.Controls.Add(message); AcceptButton=ok;
   int attempts=0; var delay=new System.Windows.Forms.Timer {Interval=5000}; delay.Tick+=(s,e)=>{ok.Enabled=true;delay.Stop();}; FormClosed+=(s,e)=>delay.Dispose();
   ok.Click+=(s,e)=>{
    if(setup) { if(Input.Text.Length<8 || Input.Text!=confirm.Text) {message.Text="Не менее 8 символов. Пароли должны совпадать.";return;} }
    else if(!Secrets.Check(c,Input.Text)) {message.Text="Неверный пароль.";Input.Clear();if(++attempts>=3){ok.Enabled=false;delay.Start();}return;}
    DialogResult=DialogResult.OK;Close();
   };
  }
 }
 class MainWindow : Form {
  Config config; ListBox list=new ListBox {Dock=DockStyle.Fill}; Label status=new Label {Dock=DockStyle.Bottom,Height=48,Padding=new Padding(10)};
  NotifyIcon tray; System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer {Interval=350};
  Dictionary<Rule,DateTime> allowed=new Dictionary<Rule,DateTime>(); HashSet<Rule> pending=new HashSet<Rule>(); bool quitting=false; bool prompting=false;
  public MainWindow(Config c) {
   config=c; Text="AppGate — пароль для приложений";Size=new Size(680,450);MinimumSize=new Size(600,400);StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);
   var title=new Label {Text="AppGate",Dock=DockStyle.Top,Height=55,Font=new Font("Segoe UI",22,FontStyle.Bold),Padding=new Padding(12,5,0,0)};
   var help=new Label {Text="● Защита включена     ○ Защита выключена\nРазрешение действует до полного закрытия приложения.",Dock=DockStyle.Top,Height=62,Padding=new Padding(12)};
   var buttons=new FlowLayoutPanel {Dock=DockStyle.Bottom,Height=92,Padding=new Padding(8)};
   Controls.Add(list);Controls.Add(help);Controls.Add(title);Controls.Add(buttons);Controls.Add(status);
   AddButton(buttons,"Добавить .exe",()=> {using(var d=new OpenFileDialog {Filter="Приложения (*.exe)|*.exe"}) if(d.ShowDialog()==DialogResult.OK) {if(string.Equals(d.FileName,Application.ExecutablePath,StringComparison.OrdinalIgnoreCase))return; if(!config.Rules.Any(x=>x.Path.Equals(d.FileName,StringComparison.OrdinalIgnoreCase)))config.Rules.Add(new Rule{Name=System.IO.Path.GetFileNameWithoutExtension(d.FileName),Path=d.FileName});Save();}});
   AddButton(buttons,"Вкл. / выкл.",()=> {var r=list.SelectedItem as Rule;if(r==null)return;if(!r.Enabled && MessageBox.Show("При включении защиты запущенное приложение будет закрыто принудительно. Сохраните работу. Продолжить?","Включить защиту",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;r.Enabled=!r.Enabled;allowed.Remove(r);pending.Remove(r);Save();});
   AddButton(buttons,"Открыть",()=>{var r=list.SelectedItem as Rule;if(r!=null)Unlock(r);});
   AddButton(buttons,"Заблокировать",()=>{var r=list.SelectedItem as Rule;if(r==null || !r.Enabled)return;if(MessageBox.Show("Закрыть приложение и снова запрашивать пароль? Несохранённая работа может быть потеряна.","Заблокировать",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;allowed.Remove(r);Target.Stop(r);});
   AddButton(buttons,"Удалить",()=>{var r=list.SelectedItem as Rule;if(r!=null){config.Rules.Remove(r);allowed.Remove(r);pending.Remove(r);Save();}});
   AddButton(buttons,"Сменить пароль",()=>{if(!Auth("Текущий пароль"))return;using(var d=new PasswordBox("Новый пароль",true,null))if(d.ShowDialog()==DialogResult.OK){Secrets.Set(config,d.Input.Text);Save();}});
   AddButton(buttons,"В трей",()=>Hide());
   AddButton(buttons,"Выход",()=>Exit());
   tray=new NotifyIcon {Icon=SystemIcons.Shield,Text="AppGate",Visible=true}; var menu=new ContextMenuStrip();menu.Items.Add("Настройки",null,(s,e)=>ShowSettings());menu.Items.Add("Выход",null,(s,e)=>Exit());tray.ContextMenuStrip=menu;tray.DoubleClick+=(s,e)=>ShowSettings();
   FormClosing+=(s,e)=>{if(!quitting){e.Cancel=true;Hide();}};
   FormClosed+=(s,e)=>{timer.Dispose();tray.Dispose();};timer.Tick+=(s,e)=>Tick();RefreshList();timer.Start();
   status.Text="Защита работает, пока AppGate запущен. Автозапуск можно включить ярлыком в папке автозагрузки Windows.";
  }
  void AddButton(Control parent,string text,Action act){var b=new Button {Text=text,AutoSize=true,Height=32};b.Click+=(s,e)=>{try{act();}catch(Exception ex){MessageBox.Show(ex.Message,"AppGate");}};parent.Controls.Add(b);}
  void RefreshList(){var selected=list.SelectedItem;list.Items.Clear();foreach(var r in config.Rules)list.Items.Add(r);if(selected!=null && list.Items.Contains(selected))list.SelectedItem=selected;}
  void Save(){Storage.Save(config);RefreshList();}
  bool Auth(string title){using(var d=new PasswordBox(title,false,config))return d.ShowDialog()==DialogResult.OK;}
  void ShowSettings(){if(prompting)return;prompting=true;try{if(Auth("Настройки AppGate")){Show();Activate();}}finally{prompting=false;}}
  void Exit(){if(Auth("Выход из AppGate")){quitting=true;Close();}}
  void Unlock(Rule r){if(prompting)return;prompting=true;try{if(Auth("Открыть: "+r.Name)){allowed[r]=DateTime.UtcNow.AddSeconds(12);pending.Remove(r);try{Target.Launch(r);}catch(Exception ex){allowed.Remove(r);MessageBox.Show(ex.Message,"Не удалось запустить");}}}finally{prompting=false;}}
  void Tick(){
   foreach(var r in config.Rules.Where(x=>x.Enabled).ToArray()) {
    var processes=Target.Find(r);bool running=processes.Count>0;foreach(var p in processes)p.Dispose();
    if(allowed.ContainsKey(r)){if(running)allowed[r]=DateTime.UtcNow.AddSeconds(2);else if(DateTime.UtcNow>allowed[r])allowed.Remove(r);continue;}
    if(running){if(!Target.Stop(r))status.Text="Не удалось закрыть "+r.Name+". Проверьте права доступа.";pending.Add(r);}
   }
   if(!prompting && pending.Count>0){var r=pending.First();pending.Remove(r);BeginInvoke(new Action(()=>Unlock(r)));}
  }
 }
 static class Program {
  [STAThread] static int Main(string[] args){
   if(args.Contains("--probe")){Thread.Sleep(30000);return 0;}
   if(args.Contains("--self-test"))return Test();
   bool fresh;using(var mutex=new Mutex(true,"Local\\AppGate-"+Environment.UserName,out fresh)){
    if(!fresh){MessageBox.Show("AppGate уже работает. Откройте его значком в трее.");return 0;}
    Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Config c;
    try {
     if(File.Exists(Storage.FileName)){c=Storage.Decode(File.ReadAllBytes(Storage.FileName));using(var d=new PasswordBox("Запуск AppGate",false,c))if(d.ShowDialog()!=DialogResult.OK)return 0;}
     else {c=new Config();using(var d=new PasswordBox("Первый запуск AppGate",true,null)){if(d.ShowDialog()!=DialogResult.OK)return 0;Secrets.Set(c,d.Input.Text);}c.Rules.Add(new Rule{Name="Codex / ChatGPT (Microsoft Store)",Path="codex-store",Enabled=false});Storage.Save(c);}
     Application.Run(new MainWindow(c));return 0;
    }catch(Exception ex){MessageBox.Show("Не удалось открыть AppGate: "+ex.Message+"\nЗащита не запущена.","AppGate",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
   }
  }
  static int Test(){try{
   var c=new Config();Secrets.Set(c,"test-password-123");if(!Secrets.Check(c,"test-password-123")||Secrets.Check(c,"wrong"))throw new Exception("Password verification");
   var encrypted=Storage.Encode(c);var restored=Storage.Decode(encrypted);if(!Secrets.Check(restored,"test-password-123"))throw new Exception("DPAPI roundtrip");
   var rule=new Rule{Path="codex-store"};string root=Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)+"\\WindowsApps\\";
   if(!Target.Match(rule,root+"OpenAI.Codex_99.0_x64__2p2nqsd0c76g0\\app\\ChatGPT.exe") || Target.Match(rule,"C:\\temp\\ChatGPT.exe") || Target.Match(rule,root+"OpenAI.Codex_99.0_x64__different\\app\\ChatGPT.exe"))throw new Exception("Package matcher");
   string probe=System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"AppGateProbe.exe");File.Copy(Application.ExecutablePath,probe,true);
   try{using(var p=Process.Start(probe,"--probe")){Thread.Sleep(700);var pr=new Rule{Path=probe};if(!Target.Stop(pr)||!p.WaitForExit(5000))throw new Exception("Process blocking");}}finally{File.Delete(probe);}
   File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-result.txt"),"PASS: password verification, wrong-password rejection, DPAPI roundtrip, Store package identity, real probe process termination.");return 0;
  }catch(Exception ex){File.WriteAllText(System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"test-result.txt"),"FAIL: "+ex);return 1;}}
 }
}
