# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "CmsEasy" do
    author "hyhm2n"
    version "0.1"
    description "是一款基于 PHP+Mysql 架构的网站内容管理系统，也是一个 PHP 开发平台。 采用模块化方式开发，功能易用便于扩展，可面向大中型站点提供重量级网站建设解决方案。"
    website "https://www.cmseasy.cn/"
    
    # Matches #    
#     {:version=>/<meta name="Generator" content="CmsEasy ([0-9_]+)">/ }
matches [
    {:text=>'<meta name="author" content="CmsEasy Team">'},
    {:text=>'<a href="https://www.cmseasy.cn"'},
    {:text=>'target="_blank">CmsEasy</a>'},
]

    end