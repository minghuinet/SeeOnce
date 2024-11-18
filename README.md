# SeeOnce
初见渗透测试工具箱
初见渗透测试工具箱是一款python编写的UI集成项目，解决平时渗透工作繁杂的工具安装及环境兼容问题，项目集成了pyhon、java等环境配置，配备了渗透所需的常用工具，开箱即用，首次发布时间于2022年10月，经过多次更新迭代，正式更名为SeeOnce
本项目只提供工具箱代码部分，由于工具资源比较大，工具部分请前往“小阿辉谈安全”微信公众号置顶文章获取
![image](https://github.com/user-attachments/assets/a519947b-b161-4896-8ed6-d3ab289ad98a)
![image](https://github.com/user-attachments/assets/dcc0f25b-ffa9-4a74-bcb5-f4d9211263a1)
![image](https://github.com/user-attachments/assets/f71c3bb2-5c98-40a4-8de2-c1c179c217d3)
![image](https://github.com/user-attachments/assets/f4e5945c-4f39-4929-90f4-5979c5b16896)
![image](https://github.com/user-attachments/assets/684a099f-0f6c-471a-ab2c-6f36d93452da)
![image](https://github.com/user-attachments/assets/e1609cf9-05f5-478d-bd11-f8e542b20ad5)
![image](https://github.com/user-attachments/assets/de13b212-7b07-4ca9-aec7-fa1a516c4ad2)


# 使用方法
windows环境下，可通过双机目录下SeeOnce.vbs脚本一键启动，创建快捷方式可配置logo图标，创建桌面快捷方式后期可直接桌面运行
![image](https://github.com/user-attachments/assets/5f3f7967-8e6f-4255-92b7-0eaf7f0f9e56)
linux环境下采用python启动
```
python3 MainUI.py
```
## 目录介绍

- informations_collect  信息收集模块工具
- webshell  webshell管理模块工具
- normal    常用工具
- tools     专用工具（如weblogic、shiro、oa）
- andrio    安卓测试工具
- Java_path   java环境变量（java8~18）
- Python38     python3环境
- 内网渗透      内网渗透工具（不展示，可自己添加）

完整目录结构如下
![image](https://github.com/user-attachments/assets/d6b5a31b-ed79-439d-b29e-415e9d2a9c70)

# 自定义工具配置
## UI控件添加
编辑MainUI.py文件，在对应模块下添加控件，如需要在安卓测试模块添加工具，则在对应位置复制以下内容
![image](https://github.com/user-attachments/assets/6bbb7477-7e76-4db4-be6d-1ca9453acc96)

```
ttk.Button(gui_XX, text="XX名称", bootstyle=(PRIMARY, "success-outline-toolbutton"),width=button_width, command=seeonce.XXX_click).grid(row=X, column=X, padx=20, pady=10)
```

## 控件触发事件添加
编辑SeeOnce.py文件，在对应模块下添加事件函数
![image](https://github.com/user-attachments/assets/cc4dfd53-cf43-43a2-919e-d68684a8abe9)
如需要在安卓测试模块ApkScan-PKID.jar，则在对应位置复制以下内容
```
    def apkscan_click(self):
        subprocess.Popen('cd andrio/ &&'+ java8_path+' -jar ApkScan-PKID.jar', shell=True)
```



