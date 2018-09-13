# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "金蝶协同办公系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "金蝶办公自动化系统，是实现企业基础管理协作平台的知识办公系统，主要面向企事业单位部门、群组和个人，进行事务、流程和信息及时高效、有序可控地协同业务处理，创建企业电子化的工作环境，通过可视化的工作流系统和知识挖掘机制建立企业知识门户。"
    website "http://www.kingdee.com/"
    
    matches [

    # Default text
    { :url=>"/images/logo-kingdee.gif", :md5=>"49f31794102571d70de87f512221b8f8" },

    # Version detection

    ]

    end
    