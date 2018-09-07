# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "DouPHP" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "DouPHP 是一款轻量级企业网站管理系统，基于PHP+Mysql架构的，可运行在Linux、Windows、MacOSX、Solaris等各种平台上，系统搭载Smarty模板引擎，支持自定义伪静态，前台模板采用DIV+CSS设计，后台界面设计简洁明了，功能简单易具有良好的用户体验，稳定性好、扩展性及安全性强，可面向中小型站点提供网站建设解决方案。"
    website "http://www.douco.com/"
    
    # Matches #
    matches [
        { :text=>"Powered by DouPHP"},
        { :version=>/<meta name="generator" content="DouPHP (<.*?>)">/}
    ]
    
    end