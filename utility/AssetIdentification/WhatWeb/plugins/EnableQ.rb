##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "EnableQ" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "EnableQ在线问卷调查引擎是一款通用的在线调查问卷管理平台。"
    website "http://www.enableq.com/"

    matches [
        { :text=>'href="http://www.enableq.com/cn/buy/price.html"'},
        { :url=>"/License/ServicesTerm.html", :md5=>"3a5c3bd0479be0b5f1c0f12dd839b590" },
        { :url=>"/Images/enableq.ico", :md5=>"651f6b2c476f06e551fd48bbee202aa9"}
    
    ]
    
    end