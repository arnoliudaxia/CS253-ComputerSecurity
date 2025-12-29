该虚拟机配置了 Debian GNU/Linux 11 (bullseye)，并关闭了 ASLR（地址随机化）。它有一个用户帐户“user”，密码为“cs253”，但您可以使用 sudo 临时成为 root 用户。

漏洞利用程序将以“user”身份运行，并应生成一个以“root”身份运行的命令行 shell (/bin/sh)。