# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "JISUCMS(极速网络CMS)" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "极速CMS政务站群内容管理系统按照政府门户网站考核标准为基础，集成信息公开、网上办事、互动交流、网络问政、在线服专题专栏等政务网站核心模块内容而开发的内容管理系统；系统同时支持信息报送、绩效考核等子系统的数据对接；站群B/S架构，支持主站跟子站独立部署，又支持数据相互互通。"
    website "http://www.90576.com"
    
    matches [

    # Default text
    { :text=>"http://www.90576.com" }

    # Version detection

    ]

    end
    