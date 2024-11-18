
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from SeeOnce import SeeOnce

# UI 宽度
width = 1400
# UI 高度
height = 450
# 按钮宽度
button_width = 25
# themes_list = ['superhero','yeti','lumen','journal','darkly','solar','morph','vapor']
# 多种主题可供切换
themes = 'solar'
#实例化类对象
seeonce = SeeOnce()
UI = ttk.Window(
                title="SeeOnce【初见V2】渗透盒子 By 小阿辉谈安全",
                themename=themes,
                size=(width, height),  #窗口(宽度，高度）
                resizable=(True, True),
                )
main_form = ttk.Frame(UI)
main_form.pack(pady=5, fill=X, side=TOP)
pk = ttk.Notebook(main_form)
pk.pack(
    side=LEFT,
    padx=(10, 0),
    expand=YES,
    fill=BOTH
)

#################### 渗透利器 ####################
gui_normal = ttk.Frame(pk)

ttk.Button(gui_normal, text="Burp_Suite_Professional_v2022.9", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.burp_suite_click).grid(row=1, column=1, padx=20, pady=10)

ttk.Button(gui_normal, text="Cobalt_Strike_4.7", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.cs_click).grid(row=1, column=2, padx=20, pady=10)

ttk.Button(gui_normal, text="Xray_Pro_1.9.11", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.xray_click).grid(row=1, column=3, padx=20, pady=10)

ttk.Button(gui_normal, text="Goby_V_2.0.5 beta", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.goby_click).grid(row=1, column=4, padx=20, pady=10)

ttk.Button(gui_normal, text="railgun1.5.5", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.railgun_click).grid(row=2, column=1, padx=20, pady=10)

ttk.Button(gui_normal, text="sqlmap", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.sqlmap_click).grid(row=2, column=2, padx=20, pady=10)

ttk.Button(gui_normal, text="TscanPlus", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.tscan_click).grid(row=2, column=3, padx=20, pady=10)

pk.add(gui_normal, text='     渗透利器    ')

#################### 信息收集 ####################
gui_shouji = ttk.Frame(pk)

ttk.Button(gui_shouji, text="超级弱口令检查工具V1.0 Beta28 20190715", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.weakbrute_click).grid(row=1, column=1, padx=20, pady=10)

ttk.Button(gui_shouji, text="7kbscan-WebPathBrute", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.webPathBrute_click).grid(row=1, column=2, padx=20, pady=10)

ttk.Button(gui_shouji, text="OneForAll-0.4.5", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.OneForAll_click).grid(row=1, column=3, padx=20, pady=10)

ttk.Button(gui_shouji, text="Ladon_10.10", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.ladon_click).grid(row=1, column=4, padx=20, pady=10)

ttk.Button(gui_shouji, text="Ladon_cmd", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.ladon_cmd_click).grid(row=2, column=1, padx=20, pady=10)

ttk.Button(gui_shouji, text="Dirsearch0.4.3", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.dirsearch_cmd_click).grid(row=2, column=2, padx=20, pady=10)

ttk.Button(gui_shouji, text="AppInfoScanner", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.appinfoscanner_cmd_click).grid(row=2, column=3, padx=20, pady=10)

ttk.Button(gui_shouji, text="SnowShadow_V_1.0", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.SnowShadow_click).grid(row=2, column=4, padx=20, pady=10)

ttk.Button(gui_shouji, text="用户名字典生成工具V0.21", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.dic_click).grid(row=3, column=1, padx=20, pady=10)

ttk.Button(gui_shouji, text="FOFA_Viewer", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.fofaviewer_click).grid(row=3, column=2, padx=20, pady=10)

ttk.Button(gui_shouji, text="Search_Viewer", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.search_viewer_click).grid(row=3, column=3, padx=20, pady=10)

ttk.Button(gui_shouji, text="EHole3.1棱洞", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.Ehole_click).grid(row=3, column=4, padx=20, pady=10)
pk.add(gui_shouji, text='     信息收集    ')

#################### WebShell管理工具 ####################
gui_webshell = ttk.Frame(pk)
            
ttk.Button(gui_webshell,text="哥斯拉_v4.0.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.godzilla_click).grid(row=1,column=1,padx=20,pady=10)
                
ttk.Button(gui_webshell,text="冰蝎_v4.0.7", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.behinder_click).grid(row=1,column=2,padx=20,pady=10)
                
ttk.Button(gui_webshell,text="冰蝎魔改_v3.3.2", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.BehinderMode_click).grid(row=1,column=3,padx=20,pady=10)
                
ttk.Button(gui_webshell,text="中国蚁剑_v2.1.14", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.antSword_click).grid(row=1,column=4,padx=20,pady=10)
                
ttk.Button(gui_webshell,text="天蝎权限管理工具_v1.0", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.tianxie_click).grid(row=2,column=1,padx=20,pady=10)

ttk.Button(gui_webshell,text="开山斧", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.kaitianfu_click).grid(row=2,column=2,padx=20,pady=10)

ttk.Button(gui_webshell,text="Webshell 生成器", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Webshell_Generate_click).grid(row=2,column=3,padx=20,pady=10)
                
pk.add(gui_webshell, text='  WebShell管理工具    ')

#################### WebLogic漏洞 ####################
gui_frame = ttk.Frame(pk)

ttk.Button(gui_frame, text="WebLogic-FrameWork", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.weblogic_click).grid(row=1, column=1, padx=20, pady=10)

ttk.Button(gui_frame, text="JAVA反序列化漏洞利用工具-WebLogic", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.weblogic_java_click).grid(row=1, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="Java反序列化漏洞利用工具V1.7", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.weblogicV17_click).grid(row=1, column=3, padx=20, pady=10)

ttk.Button(gui_frame, text="weblogic_exploit-1.0-SNAPSHOT-all", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.weblogic1_click).grid(row=1, column=4, padx=20, pady=10)

ttk.Button(gui_frame, text="Java反序列化终极测试工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.javafan_click).grid(row=2, column=1, padx=20, pady=10)

ttk.Button(gui_frame, text="WeblogicExploit-GUI by sp4z", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.WeblogicExploit_GUI_click).grid(row=2, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="WeblogicTool_1.2", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.WeblogicTool_click).grid(row=2, column=3, padx=20, pady=10)


#################### Struts2漏洞利用 ####################
ttk.Button(gui_frame, text="Struts2全版本漏洞检查工具19.32", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.struts2_chek1_click).grid(row=3, column=1, padx=20, pady=10)



ttk.Button(gui_frame, text="Struts_2_全版本漏洞检测工具_18.09_过waf版", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.struts2_chek_click).grid(row=3, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="K8_Struts2_EXP", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.struts2_k8_click).grid(row=3, column=3, padx=20, pady=10)

#################### Shrio漏洞利用 ####################
ttk.Button(gui_frame, text="shiro反序列化综合利用工具v2.2", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiro_attack_click).grid(row=4, column=1, padx=20, pady=10)

ttk.Button(gui_frame, text="ShiroExp", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiroexp_click).grid(row=4, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="Shiro反序列化回显工具v2.3", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiroexploit_click).grid(row=4, column=3, padx=20, pady=10)

ttk.Button(gui_frame, text="ShiroExploit", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiroexploit1_cilck).grid(row=4, column=4, padx=20, pady=10)

ttk.Button(gui_frame, text="Shiro反序列化检查工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiroscan_click).grid(row=5, column=1, padx=20, pady=10)


ttk.Button(gui_frame, text="shiro反序列化综合利用工具增强版", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.Shiro_attack2_click).grid(row=5, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="shiro反序列化批量检测工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.Shiro_detects_click).grid(row=5, column=3, padx=20, pady=10)

ttk.Button(gui_frame, text="shiro反序列化利用工具shiro_tool", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.shiro_tool_click).grid(row=5, column=4, padx=20, pady=10)


#################### ThinkPHP漏洞利用 ####################

ttk.Button(gui_frame, text="Thinkphp全网GUI圈子社区专版", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp_GUI_click).grid(row=6, column=1, padx=20, pady=10)

ttk.Button(gui_frame, text="ThinkPHP综合利用工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp_click).grid(row=6, column=2, padx=20, pady=10)

ttk.Button(gui_frame, text="ThinkPHP日志分析", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp_log_click).grid(row=6, column=3, padx=20, pady=10)

ttk.Button(gui_frame, text="ThinkLog By 莲花", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp1_log_click).grid(row=6, column=4, padx=20, pady=10)

ttk.Button(gui_frame, text="ThinkphpGUI By 莲花", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp1_click).grid(row=7, column=1, padx=20, pady=10)

ttk.Button(gui_frame, text="thinkphp命令执行检测工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.thinkphp2_click).grid(row=7, column=2, padx=20, pady=10)

pk.add(gui_frame, text='    主流框架漏洞利用    ')

#################### 安卓测试 ####################
gui_andrio = ttk.Frame(pk)
ttk.Button(gui_andrio, text="ApkScan查壳", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.apkscan_click).grid(row=1, column=1, padx=20, pady=10)

ttk.Button(gui_andrio, text="jadx-gui-1.4.7", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.jadx_click).grid(row=1, column=2, padx=20, pady=10)

ttk.Button(gui_andrio, text="AndrioKiller1.3", bootstyle=(PRIMARY, "success-outline-toolbutton"),
           width=button_width, command=seeonce.AndrioKiller_click).grid(row=1, column=3, padx=20, pady=10)

pk.add(gui_andrio, text='     Andrio安全测试    ')


#################### 综合利用 ####################
gui_scan = ttk.Frame(pk)
            
ttk.Button(gui_scan,text="Thelostworld_OA_V1.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.oaexp_click).grid(row=1,column=1,padx=20,pady=10)
                
ttk.Button(gui_scan,text="通达OA综合利用工具_v210317", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.tdoa_click).grid(row=1,column=2,padx=20,pady=10)
                
ttk.Button(gui_scan,text="Gr33k漏洞利用工具集_Win", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.gr33k_click).grid(row=1,column=3,padx=20,pady=10)
                
ttk.Button(gui_scan,text="Cas反序列化漏洞利用工具_v1.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.cas_click).grid(row=1,column=4,padx=20,pady=10)
                
ttk.Button(gui_scan,text="神机_V1.9", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.sj_click).grid(row=2,column=1,padx=20,pady=10)
                
ttk.Button(gui_scan,text="深X服EDR任意用户登陆检测工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.edr_click).grid(row=2,column=2,padx=20,pady=10)

                
ttk.Button(gui_scan,text="OracleShell_v0.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.oracleshell_click).grid(row=2,column=3,padx=20,pady=10)
                
ttk.Button(gui_scan,text="FrameScan_GUI_Win_v1.3.8", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.framescan_click).grid(row=2,column=4,padx=20,pady=10)
                
ttk.Button(gui_scan,text="Tomcat弱口令爆破", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.tomcat_password_click).grid(row=3,column=1,padx=20,pady=10)

ttk.Button(gui_scan,text="Redis漏洞利用工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.redisexp_click).grid(row=3,column=2,padx=20,pady=10)
                
ttk.Button(gui_scan,text="FastJson检测工具_Win", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.fastjson_cilck).grid(row=3,column=3,padx=20,pady=10)
                
ttk.Button(gui_scan,text="FastJson_JackSon漏洞利用", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.FastJson_JackSon_click).grid(row=3,column=4,padx=20,pady=10)
                
ttk.Button(gui_scan,text="CVE-2020-10199", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.cve_2020_10199_click).grid(row=4,column=1,padx=20,pady=10)
                
ttk.Button(gui_scan,text="CVE-2019-7238", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.cve_2019_7238_click).grid(row=4,column=2,padx=20,pady=10)
                
ttk.Button(gui_scan,text="阿里云Accesskey利用工具_V1.2_Win", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.aliyun_accesskey_click).grid(row=4,column=3,padx=20,pady=10)
                
ttk.Button(gui_scan,text="AliyunAkTools_Win", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.aliyunakyools_click).grid(row=4,column=4,padx=20,pady=10)
                
ttk.Button(gui_scan,text="MDUT_v2.1.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.mdut_click).grid(row=5,column=1,padx=20,pady=10)
                
ttk.Button(gui_scan,text="Liqun工具箱1.5.1", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Liqunkit_click).grid(row=5,column=2,padx=20,pady=10)
                
ttk.Button(gui_scan,text="蓝队分析辅助工具箱V0.85", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.BlueTeamTools_click).grid(row=5,column=3,padx=20,pady=10)
                
ttk.Button(gui_scan,text="海康威视配置文件解密", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.hikvision_click).grid(row=5,column=4,padx=20,pady=10)

ttk.Button(gui_scan,text="通达OA解密", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.TongDA_click).grid(row=6,column=1,padx=20,pady=10)

ttk.Button(gui_scan,text="Seay-Svn源代码泄露漏洞", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.eaySvn_click).grid(row=6,column=2,padx=20,pady=10)

ttk.Button(gui_scan,text="Tomcat-CVE-2021-41773验证工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.tomcat_click).grid(row=6,column=3,padx=20,pady=10)

ttk.Button(gui_scan,text="poc2jar_V0.61", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.poc2_click).grid(row=6,column=4,padx=20,pady=10)

ttk.Button(gui_scan,text="NC-rce检测工具", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.nc_click).grid(row=7,column=1,padx=20,pady=10)

ttk.Button(gui_scan,text="SpringBootExploit_V1.3", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.SpringBootExploit_click).grid(row=7,column=2,padx=20,pady=10)

ttk.Button(gui_scan,text="APItools 钉钉、企业微信、飞书", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.APItools_click).grid(row=7,column=3,padx=20,pady=10)

pk.add(gui_scan, text='     漏洞利用    ')

#################### WIKI ####################
gui_wiki = ttk.Frame(pk)
ttk.Button(gui_wiki,text="Ladon Wiki", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Ladon_Wiki_click).grid(row=1,column=1,padx=20,pady=10)

ttk.Button(gui_wiki,text="CobaltStrike Wiki", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.CS_Wiki_click).grid(row=1,column=2,padx=20,pady=10)

ttk.Button(gui_wiki,text="CMD命令大全", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.CMD_Wiki_click).grid(row=1,column=3,padx=20,pady=10)

ttk.Button(gui_wiki,text="Linux命令大全", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Linux_Wiki_click).grid(row=1,column=4,padx=20,pady=10)

ttk.Button(gui_wiki,text="免杀手册", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Bypass_Wiki_click).grid(row=2,column=1,padx=20,pady=10)

ttk.Button(gui_wiki,text="字符对照表", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.Charator_Wiki_click).grid(row=2,column=2,padx=20,pady=10)

ttk.Button(gui_wiki,text="工具使用说明", bootstyle=(PRIMARY, "success-outline-toolbutton"),
            width=button_width, command=seeonce.tools_Wiki_click).grid(row=2,column=3,padx=20,pady=10)
pk.add(gui_wiki, text='     WIKI文库    ')
UI.mainloop()
        