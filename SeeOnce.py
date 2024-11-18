import subprocess
from setting import java8_path
from setting import java11_path
class SeeOnce():
    # WebShell管理工具
    def godzilla_click(self):
        subprocess.Popen("cd webshell/Godzilla && " + java8_path + ' -jar ' + 'Godzilla.jar', shell=True)

    def behinder_click(self):
        subprocess.Popen("cd webshell/Behinder_v4.07 && " + java8_path + ' -jar ' + 'Behinder.jar', shell=True)

    def BehinderMode_click(self) :
        subprocess.Popen("cd webshell/Behinder-Mode && " + java8_path + ' -jar ' + 'Behinder-Mode.jar', shell=True)

    def antSword_click(self) :
        subprocess.Popen('cd webshell/AntSword/AntSword-Loader-v4.0.3-win32-x64 && AntSword.exe', shell=True)

    def tianxie_click(self) :
        subprocess.Popen("cd webshell/TianXie && " + java8_path + ' -jar ' + '天蝎权限管理工具.jar', shell=True)

    def kaitianfu_click(self) :
        subprocess.Popen("cd webshell/开天斧 && main.exe", shell=True)

    def Webshell_Generate_click(self) :
        subprocess.Popen("cd webshell/ && " + java8_path + ' -jar ' + 'Webshell_Generate-1.1.jar', shell=True)

    # 渗透测试工具
    def burp_suite_click(self) :
        subprocess.Popen(
            "cd normal/burpsuite_pro && " + java11_path + ' -Xmx2048m -Dfile.encoding=utf-8 '
                                                          '-javaagent:BurpSuiteCnV2.0.jar '
                                                          '--illegal-access=permit -Dfile.encoding=utf-8 '
                                                          '-javaagent:ja-netfilter.jar '
                                                          '-noverify -jar burpsuite_pro_v2022.9.jar ', shell=True)

    def cs_click(self) :
        subprocess.Popen(
            "cd normal/Cobalt_Strike_4.7/ && " + java11_path + ' -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -javaagent:CSAgent.jar=CSAgent.properties -Duser.language=en -jar cobaltstrike-client.jar %*",0 ',
            shell=True)

    def xray_click(self) :
        subprocess.Popen('cd normal/xray_1.9.11 && ' + java11_path + ' -jar super-xray-0.5-beta.jar', shell=True)

    def goby_click(self) :
        subprocess.Popen('cd normal/Goby && Goby.exe', shell=True)

    def railgun_click(self) :
        subprocess.Popen('cd normal/railgun1.5.5 && gorailgun-normal-1.5.5.exe', shell=True)

    def sqlmap_click(self) :
        subprocess.Popen('cd normal\sqlmap && start.bat', shell=True)

    def tscan_click(self) :
        subprocess.Popen('cd normal\TscanPlus && TscanPlus_windows_amd64_v1.8-upx.exe', shell=True)

    # 信息收集工具
    def weakbrute_click(self) :
        subprocess.Popen("cd informations_collect/超级弱口令检查工具V1.0 Beta28 20190715 && SNETCracker.exe", shell=True)

    def webPathBrute_click(self) :
        subprocess.Popen('cd informations_collect/7kbscan-WebPathBrute.1.6.2 && 7kbscan-WebPathBrute.exe', shell=True)

    def OneForAll_click(self) :
        subprocess.Popen('cd informations_collect/OneForAll-0.4.5 && start.bat', shell=True)

    def ladon_click(self) :
        subprocess.Popen('cd informations_collect\Ladon10.0 && LadonGUI.exe', shell=True)

    def ladon_cmd_click(self) :
        subprocess.Popen('cd informations_collect\Ladon10.10 && cmd.bat', shell=True)

    def dirsearch_cmd_click(self) :
        subprocess.Popen('cd informations_collect\dirsearch-0.4.3 && start.bat', shell=True)

    def appinfoscanner_cmd_click(self) :
        subprocess.Popen('cd informations_collect\AppInfoScanner && cmd.bat', shell=True)

    def SnowShadow_click(self) :
        subprocess.Popen('cd informations_collect/SnowShadow/SnowShadow_v1.0 && SnowShadow.exe', shell=True)

    def dic_click(self):
        subprocess.Popen("cd informations_collect/用户名字典生成工具V0.21 && " + java8_path + ' -jar ' + '用户名字典生成工具V0.21.jar', shell=True)

    def fofaviewer_click(self):
        subprocess.Popen("cd informations_collect/fofaviewer && " + java8_path + ' -jar ' + 'fofaviewer.jar', shell=True)

    def search_viewer_click(self):
        subprocess.Popen("cd informations_collect/search_viewer && Search_Viewer.exe", shell=True)

    def Ehole_click(self):
        subprocess.Popen("cd informations_collect/EHole3.1 && start.bat", shell=True)
    # 漏洞扫描工具
    def oaexp_click(self) :
        subprocess.Popen("cd tools/Thelostworld_OA && " + java8_path + ' -jar ' + 'Thelostworld_OA.jar', shell=True)

    def tdoa_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + 'TDOA20210726.jar', shell=True)

    def gr33k_click(self) :
        subprocess.Popen('cd tools/Gr33k && Gr33k.exe', shell=True)

    def cas_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + 'CAS_cc2_Exploit-1.0-SNAPSHOTv1.1-all.jar',
                         shell=True)

    def sj_click(self) :
        subprocess.Popen("cd tools/ExpDemo-JavaFX-By-SJ && " + java8_path + ' -jar ' + 'SJ-V1.9.jar', shell=True)

    def thinkphp_GUI_click(self) :
        subprocess.Popen('cd tools/thinkphp && Thinkphp全网GUI圈子社区专版.exe', shell=True)

    def thinkphp_click(self) :
        subprocess.Popen("cd tools/thinkphp && " + java8_path + ' -jar ' + 'ThinkPHP综合利用工具.jar', shell=True)

    def thinkphp_log_click(self) :
        subprocess.Popen('cd tools/thinkphp && ThinkPHP.v1.2_Beta.exe', shell=True)

    def thinkphp1_log_click(self) :
        subprocess.Popen("cd tools/thinkphp && " + java8_path + ' -jar ' + 'ThinkLog-1.0-SNAPSHOT.jar',
                         shell=True)

    def thinkphp1_click(self) :
        subprocess.Popen("cd tools/thinkphp && " + java8_path + ' -jar ' + 'ThinkphpGUI-1.2-SNAPSHOT.jar',
                         shell=True)

    def thinkphp2_click(self) :
        subprocess.Popen("cd tools/thinkphp && " + java8_path + ' -jar ' + 'thinkphp命令执行检测工具.jar', shell=True)

    def weblogic_click(self) :
        subprocess.Popen(
            "cd tools/weblogic && " + java8_path + ' -jar ' + 'weblogic-framework.jar',
            shell=True)

    def weblogic_java_click(self) :
        subprocess.Popen(
            "cd tools/weblogic && " + java8_path + ' -jar ' + 'JAVA反序列化漏洞利用工具-WebLogic.jar',
            shell=True)

    def weblogicV17_click(self) :
        subprocess.Popen(
            "cd tools/weblogic && " + java8_path + ' -jar ' + 'Java反序列化漏洞利用工具V1.7.jar',
            shell=True)

    def weblogic1_click(self) :
        subprocess.Popen("cd tools/weblogic && " + java8_path + ' -jar ' + 'weblogic_exploit-1.0-SNAPSHOT-all.jar',
                         shell=True)

    def WeblogicExploit_GUI_click(self) :
        subprocess.Popen("cd tools/weblogic/WeblogicExploit-GUI && " + java8_path + ' -jar ' + 'Weblogic-GUI.jar',
                         shell=True)
    def WeblogicTool_click(self) :
        subprocess.Popen("cd tools/weblogic/ && " + java8_path + ' -jar ' + 'WeblogicTool_1.2.jar',
                         shell=True)

    def javafan_click(self) :
        subprocess.Popen("cd tools/weblogic && " + java8_path + ' -jar ' + 'Java反序列化终极测试工具.jar',
                         shell=True)

    def edr_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + '深X服edr任意用户登陆检测工具.jar', shell=True)

    def shiro_attack_click(self) :
        subprocess.Popen("cd tools/shiro/shiro_attack_2.2 && " + java8_path + ' -jar ' + 'shiro_attack-2.2.jar',
                         shell=True)

    def shiroexp_click(self) :
        subprocess.Popen("cd tools/shiro && " + java8_path + ' -jar ' + 'ShiroExp.jar', shell=True)

    def shiroexploit_click(self) :
        subprocess.Popen("cd tools/shiro && " + java8_path + ' -jar ' + 'ShiroExploit-v2.3.jar', shell=True)

    def shiroexploit1_cilck(self) :
        subprocess.Popen("cd tools/shiro && " + java8_path + ' -jar ' + 'ShiroExploit.jar', shell=True)

    def shiroscan_click(self) :
        subprocess.Popen("cd tools/shiro && " + java8_path + ' -jar ' + 'ShiroScan-1.1.jar', shell=True)


    def Shiro_attack2_click(self) :
        subprocess.Popen(
            "cd tools/shiro/shiro_attack2 && " + java8_path + ' -jar ' + 'shiro_attack-4.6.0-SNAPSHOT-all.jar',
            shell=True)

    def Shiro_detects_click(self) :
        subprocess.Popen(
            "cd tools/shiro/shiro_killer-1.0.0 && start.bat",shell=True)

    def shiro_tool_click(self) :
        subprocess.Popen(
            "cd tools/shiro/ && start.bat",shell=True)

    def oracleshell_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + 'oracleShell.jar', shell=True)

    def framescan_click(self) :
        subprocess.Popen("cd tools/FrameScan-GUI.v1.4.2 && FrameScan-GUI.exe", shell=True)

    def tomcat_password_click(self) :
        subprocess.Popen("cd tools/tomcat && " + java8_path + ' -jar ' + 'tomcat.jar', shell=True)

    def fastjson_cilck(self) :
        subprocess.Popen("cd tools/json && json反序列化检查工具.exe", shell=True)

    def FastJson_JackSon_click(self) :
        subprocess.Popen("cd tools/FastJson_JackSon && " + java8_path + " -jar FastJson_JackSon.jar",
                         shell=True)


    def cve_2020_10199_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + 'cve-2020-10199-10204.jar', shell=True)

    def cve_2019_7238_click(self) :
        subprocess.Popen("cd tools && " + java8_path + ' -jar ' + 'cve-2019-7238.jar', shell=True)

    def aliyun_accesskey_click(self) :
        subprocess.Popen('cd tools && Aliyun-.AK.Tools-V1.2.exe', shell=True)

    def aliyunakyools_click(self) :
        subprocess.Popen('cd tools/AliyunAkTools && AliyunAkTools.exe', shell=True)

    def mdut_click(self) :
        subprocess.Popen(
            "cd tools/Multiple.Database.Utilization.Tools && " + java8_path + ' -jar ' + 'Multiple.Database.Utilization.Tools-2.1.1-jar-with-dependencies.jar',
            shell=True)

    def Liqunkit_click(self) :
        subprocess.Popen(
            "cd tools/LiqunKit_1.5.1 && " + java8_path + ' -jar ' + 'LiqunKit_1.5.1.jar', shell=True)

    def BlueTeamTools_click(self) :
        subprocess.Popen("cd tools/BlueTeamToolsV1.08 && " + java8_path + " -jar BlueTeamToolsV1.08.jar",
                         shell=True)

    def hikvision_click(self) :
        subprocess.Popen('cd tools && hikvision-decrypter.exe', shell=True)

    def TongDA_click(self) :
        subprocess.Popen('cd tools && SeayDzend.exe', shell=True)

    def eaySvn_click(self) :
        subprocess.Popen('cd tools && Seay-Svn源代码泄露漏洞利用工具.exe', shell=True)

    def tomcat_click(self) :
        subprocess.Popen('cd tools && CVE-2021-41773.exe', shell=True)

    def poc2_click(self) :
        subprocess.Popen("cd tools/poc2jar-WINDOWS && " + java8_path + ' -jar ' + 'poc2jar.jar', shell=True)

    def nc_click(self) :
        subprocess.Popen("cd tools && " + java8_path + " -jar " + "NC_Rce.jar", shell=True)

    def SpringBootExploit_click(self) :
        subprocess.Popen("cd tools/spring && " + java8_path + ' -jar ' + 'SpringBootExploit-1.3-SNAPSHOT-all.jar',
                         shell=True)

    def redisexp_click(self):
        subprocess.Popen("cd tools/RedisEXP/cmd && start.bat", shell=True)

    def APItools_click(self):
        subprocess.Popen("cd tools &&" + java8_path + ' -jar '+'API-T00L_v1.2.jar', shell=True)

    # struts2漏洞工具
    def struts2_k8_click(self) :
        subprocess.Popen('cd tools/struts2 && K8_Struts2_EXP.exe', shell=True)


    def struts2_chek_click(self) :
        subprocess.Popen("cd tools/struts2 && " + java8_path + ' -jar ' + 'Struts_2_全版本漏洞检测工具_18.09_过waf版.jar',
                         shell=True)

    def struts2_chek1_click(self) :
        subprocess.Popen("cd tools/struts2 && " + java8_path + ' -jar ' + 'Struts2_19.32.jar', shell=True)




    #######wiki#####
    def Ladon_Wiki_click(self) :
        subprocess.Popen("cd informations_collect/Ladon10.0 && wiki.txt",
                         shell=True)
    def CS_Wiki_click(self) :
        subprocess.Popen("cd normal/Cobalt_Strike_4.7 && wiki.txt",
                         shell=True)

    def CMD_Wiki_click(self) :
        subprocess.Popen("cd normal/wiki/ && CMD命令大全.txt",shell=True)

    def Charator_Wiki_click(self):
        subprocess.Popen("cd normal/wiki/ && 字符对照表.txt", shell=True)

    def Linux_Wiki_click(self):
        subprocess.Popen("cd normal/wiki/ && linux中文man在线手册.chm", shell=True)

    def Bypass_Wiki_click(self):
        subprocess.Popen("cd normal/wiki && 免杀入门电子书.chm", shell=True)

    def tools_Wiki_click(self):
        subprocess.Popen("cd normal/wiki && 工具使用手册.txt", shell=True)

    # Andrio安全测试工具
    def apkscan_click(self):
        subprocess.Popen('cd andrio/ &&'+ java8_path+' -jar ApkScan-PKID.jar', shell=True)

    def AndrioKiller_click(self):
        subprocess.Popen('cd andrio/AndroidKiller_v1.3.12018 && AndroidKiller.exe', shell=True)

    def jadx_click(self):
        subprocess.Popen('cd andrio/jadx-gui-1.4.7with-jre-win && jadx-gui-1.4.7.141-37b1bff8.exe', shell=True)