##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "ExtMail" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "Extmail 是一个以perl语言编写，面向大容量/ISP级应用，免费的高性能Webmail软件，主要包括ExtMail、Extman两个部分的程序套件。ExtMail套件用于提供从浏览器中登录、使用邮件系统的Web操作界面，而Extman套件用于提供从浏览器中管理邮件系统的Web操作界面。它以GPL版权释出，设计初衷是希望设计一个适应当前高速发展的IT应用环境，满足用户多变的需求，能快速进行开发、改进和升级，适应能力强的webmail系统。"
    website "http://www.extmail.org/"

    matches [
        { :text=>'<a href="http://www.linseek.com" title="ExtMail  LinSeek'},
        { :text=>'<a href="http://www.extmail.org" title="ExtMail  LinSeek'},
        { :version=>/ExtMail .*? (V.+) Copyright/}

    
    ]
    
    end