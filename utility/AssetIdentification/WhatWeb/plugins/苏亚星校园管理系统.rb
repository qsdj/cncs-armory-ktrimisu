# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "苏亚星校园管理系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "苏亚星校园网软件系统是一个校务管理系统、资源库管理系统、VOD点播系统、校园网站和虚拟社区进行整合而形成的校园网综合应用平台。"
    website "http://www.suyaxing.com/"
    
    matches [

    # Default text
    # intext:技术支持：南京苏亚星资讯科技开发有限公司
    { :text=>'<a href="mailto:ahhn26z@sina.com">ahhn26z@sina.com</a>'  },

    # Version detection

    ]

    end
    