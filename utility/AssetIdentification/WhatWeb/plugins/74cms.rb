# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "74CMS(骑士CMS)" do
    author "hyhm2n <admin@imipy.com>" # 20180829
    version "0.1"
    description "骑士cms人才系统，是一项基于PHP+MYSQL为核心开发的一套免费 + 开源专业人才网站系统。软件具执行效率高、模板自由切换、后台管理功能方便等诸多优秀特点。"
    website "http://www.74cms.com"
    
    matches [
    { :text=>"Powered by <a href=\"http://www.74cms.com\">74cms</a>" },
    { :text=>'<meta name="copyright" content="74cms.com">'},
    ]
    
    end
    