package com.r4v3zn.weblogic.tools;

import com.r4v3zn.weblogic.tools.annotation.Authors;
import com.r4v3zn.weblogic.tools.annotation.Dependencies;
import com.r4v3zn.weblogic.tools.annotation.Versions;
import com.r4v3zn.weblogic.tools.gadget.ObjectPayload;
import com.r4v3zn.weblogic.tools.payloads.VulTest;
import com.r4v3zn.weblogic.tools.utils.StringUtils;

import java.util.*;

/**
 * Title: Main
 * Descrption: 程序主入口
 * Date:2020/3/23 22:34
 * Email:woo0nise@gmail.com
 * Company:www.j2ee.app
 * @author R4v3zn
 * @version 1.0.0
 */
public class Main {
    public static void main(String[] args) {
        VulTest.Utils.getVulTest();
        final List<Class<? extends VulTest>> vulClasses =
                new ArrayList<Class<? extends VulTest>>(VulTest.Utils.getVulTest());
        Collections.sort(vulClasses, new StringUtils.ToStringComparator()); // alphabetize
        final List<String[]> rows = new LinkedList<String[]>();
        rows.add(new String[] {"Vul", "Authors", "Dependencies", "Version"});
        rows.add(new String[] {"-------", "-------", "-------", "-------"});
        for (Class<? extends VulTest> payloadClass : vulClasses) {
            rows.add(new String[] {
                    payloadClass.getSimpleName(),
                    StringUtils.join(Arrays.asList(Authors.Utils.getAuthors(payloadClass)), ", ", "@", ""),
                    StringUtils.join(Arrays.asList(Dependencies.Utils.getDependenciesSimple(payloadClass)),", ", "", ""),
                    StringUtils.join(Arrays.asList(Versions.Utils.getVersionsSimple(payloadClass)),", ", "", "")
            });
        }

        final List<String> lines = StringUtils.formatTable(rows);

        for (String line : lines) {
            System.err.println("     " + line);
        }
    }
}