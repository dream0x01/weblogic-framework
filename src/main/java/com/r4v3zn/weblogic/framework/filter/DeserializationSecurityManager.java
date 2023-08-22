package com.r4v3zn.weblogic.framework.filter;

import java.io.SerializablePermission;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;

/**
 * @author R4v3zn woo0nise@gmail.com
 * @version 1.0.0
 */
public class DeserializationSecurityManager extends SecurityManager {

    /**
     * 白名单包
     */
    private static final List<String> ALLOWED_PACKAGE_PREFIX = new ArrayList<String>(){{
        add("com.r4v3zn.weblogic.framework.ui");
        add("com.r4v3zn.weblogic.framework.filter");
        add("com.r4v3zn.weblogic.framework.call");
        add("com.r4v3zn.weblogic.framework.utils");
        add("com.r4v3zn.weblogic.framework.vuls.impl");
        add("java.io");
        add("java.lang");
    }};
    /**
     * 白名单类
     */
    private static final List<String> ALLOWED_CLASS = new ArrayList<String>(){{add("javax.naming.InitialContext");
            add("javax.naming.spi.NamingManager");
            add("javax.rmi.CORBA.Util");
            add("org.omg.CORBA.portable.ObjectImpl");
            add("org.omg.CORBA_2_3.portable.InputStream");
            add("org.omg.CORBA_2_3.portable.OutputStream");
            add("weblogic.cluster.singleton.ClusterMasterRemote_IIOP_WLStub");
            add("weblogic.corba.cos.naming._NamingContextAnyStub");
            add("weblogic.corba.idl.AnyImpl");
            add("weblogic.corba.idl.RemoteDelegateImpl");
            add("weblogic.corba.j2ee.naming.ContextImpl");
            add("weblogic.corba.j2ee.naming.InitialContextFactoryImpl");
            add("weblogic.corba.j2ee.naming.ORBHelper");
            add("weblogic.corba.orb.ORB");
            add("weblogic.corba.utils.ValueHandlerImpl");
            add("weblogic.factories.iiop.iiopEnvironmentFactory");
            add("weblogic.iiop.ConnectionManager");
            add("weblogic.iiop.csi.ClientSecurityContext");
            add("weblogic.iiop.csi.SASServiceContext");
            add("weblogic.iiop.EndPointImpl");
            add("weblogic.iiop.IIOPInputStream");
            add("weblogic.iiop.IIOPOutputStream");
            add("weblogic.iiop.IIOPRemoteRef");
            add("weblogic.iiop.IOPProfile");
            add("weblogic.iiop.IOR");
            add("weblogic.iiop.IORManager");
            add("weblogic.iiop.LocateRequestMessage");
            add("weblogic.iiop.Message");
            add("weblogic.iiop.MuxableSocketIIOP");
            add("weblogic.iiop.ObjectKey");
            add("weblogic.iiop.ObjectOutputStreamImpl");
            add("weblogic.iiop.OutboundRequestImpl");
            add("weblogic.iiop.ReplyMessage");
            add("weblogic.iiop.RequestMessage");
            add("weblogic.iiop.SendingContextRunTime");
            add("weblogic.iiop.ServiceContext");
            add("weblogic.iiop.ServiceContextList");
            add("weblogic.iiop.TargetAddress");
            add("weblogic.jndi.Environment");
            add("weblogic.jndi.WLInitialContextFactory");
            add("weblogic.kernel.ExecuteThread");
            add("weblogic.socket.BaseAbstractMuxableSocket");
            add("weblogic.socket.JavaSocketMuxer");
            add("weblogic.socket.SocketMuxer");
            add("weblogic.socket.SocketReaderRequest");
            add("weblogic.utils.io.ObjectStreamClass");
            add("weblogic.work.ExecuteRequestAdapter");
    }};

    @Override
    public void checkPermission(Permission permission) {
        if(!(permission instanceof SerializablePermission)){
            return;
        }
        // 检查类和包名
        Class<?>[] context = getClassContext();
        for (Class<?> clazz : context) {
            if (isAllowedClass(clazz)){
                continue;
            }
            throw new SecurityException("类 " + clazz.getName() + " 不允许进行反序列化操作！");
        }
    }

    private boolean isAllowedClass(Class clazz) {
        if (ALLOWED_CLASS.contains(clazz.getName())){
            return true;
        }
        String packageName = clazz.getPackage().getName();
        for (String packagePrefix:ALLOWED_PACKAGE_PREFIX) {
            if (!packagePrefix.equals(packageName)){
                continue;
            }
            return true;
        }
        return false;
    }
}
