import os 
import platform
# 获取当前绝对路径
tools_path = os.getcwd()
if platform.system() == 'Windows' :
        java8_path = (tools_path + "\Java_Path\Java_8_win\\bin\java").replace("\\", "\\\\")
        java9_path = (tools_path + "\Java_Path\Java_9_win\\bin\java").replace("\\", "\\\\")
        java11_path = (tools_path + "\Java_Path\Java_11_win\\bin\java").replace("\\", "\\\\")
        java17_path = (tools_path + "\Java_path\Java_17_win\\bin\java").replace("\\", "\\\\")
        java18_path = (tools_path + "\Java_path\Java_18_win\\bin\java").replace("\\", "\\\\")
else:
        #MacOS和Linux的java绝对路径
        java8_path = tools_path + "/Java_path/java8/bin/java"
        java9_path = tools_path + "/Java_path/java9/bin/java"
