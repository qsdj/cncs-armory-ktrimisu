# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "蓝凌EIS智慧协同平台" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "蓝凌EIS智慧协同平台功能涵盖协同管理、知识管理、文化管理、个人工作及移动办公、项目管理、资源管理等多项扩展应用，充分满足成长型企业的各项需求。"
    website "http://www.landray.com.cn"
    
    matches [

    # Default text
    { :text=>'href="http://www.landray.com.cn/"'  },

    # Version detection

    ]

    end
    