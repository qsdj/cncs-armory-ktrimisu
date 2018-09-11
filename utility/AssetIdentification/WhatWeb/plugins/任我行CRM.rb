# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "任我行CRM" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "任我行CRM软件，是构架在互联网上，以客户为中心，以销售团队或营销系统管理为核心，以规范企业系统性和流程性、提升执行力为诉求的，涉及企业全方位资源管理的“企业运营管理平台”(Enterprise Operation Management Platform)。"
    website "http://www.wecrm.com/"
    
    matches [

    # Default text
    { :text=>"CRM_RuntimeLog" },

    # Version detection

    ]
    
    end
    