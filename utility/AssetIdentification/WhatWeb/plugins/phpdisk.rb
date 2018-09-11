##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "PHPDisk" do
    author "hyhm2n"
    version "0.1"
    description "PHPDisk是一套采用PHP和MySQL构建的网络硬盘(文件存储管理)系统，可替代传统的FTP文件管理。友好的界面，操作的便捷深受用户的欢迎。是一套可用于网络上文件办公、共享、传递、查看的多用户文件存储系统。广泛应用于互联网、公司、网吧、学校等地管理及使用文件，多方式的共享权限，全方位的后台管理，满足从个人到企业各方面应用的需求。"
    website "http://www.phpdisk.com/"
    # Matches #
    matches [
        {:text=>'<meta name="Copyright" content="Powered by PHPDisk Team, V-Core File Edition'},
        {:version=>/<meta name="generator" content="PHPDisk (.+)">/},
        {:text=>'Powered by <a href="http://www.phpdisk.com/" target="_blank">PHPDisk Team</a> V-Core File Edition'}
    ]
end
