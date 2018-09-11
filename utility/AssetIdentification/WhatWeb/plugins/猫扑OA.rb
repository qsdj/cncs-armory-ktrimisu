# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "猫扑OA" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "猫扑OA采用行业领先的云计算技术，基于传统互联网和移动互联网，创新云服务+云终端的应用模式， 为企业用户版提供一账号管理聚合应用服务。"
    website "https://www.oooa.cn/"
    
    matches [

    # Default text
    # 猫扑OA Version2014
    { :text=>'023-68185328 13996155309'  },

    # Version detection

    ]

    end
    