# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "悟空CRM" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "悟空CRM系统是一款开源免费的通用企业客户关系管理平台软件,采用先进的LAMP架构,具有良好的开放性、可扩展性、安全性和透明性。"
    website "http://www.5kcrm.com/"
    
    matches [

    # Default text
    # powered by 悟空CRM
    { :text=>'href="http://www.5kcrm.com/"'  },
    { :text=>'href="http://www.5kcrm.com/index.php?m=feedback&a=contact"' },

    # Version detection

    ]

    end
    