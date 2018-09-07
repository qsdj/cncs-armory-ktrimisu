# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "DuomiCMS" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "DuomiCms采用PHP+MYSQL架构,原生PHP代码带来卓越的访问速度和负载能力免去您的后顾之优。是一套专为影视站长而设计的视频点播系统，灵活，方便，人性化设计简单易用是最大的特色，是快速架设视频网站首选，只需3分钟即可建立一个海量的视频讯息的行业网站。"
    website "https://duomicms.net"
    
    # Matches #
    matches [
        { :text=>"Power by DuomiCms"},
        { :version=>/\(DuomiCms (.+)\)/},
    ]
    
    end