# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "海天OA" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "海天网络协同办公系统(海天OA)，是一套高质量、高效率、智能化的基于B/S结构的办公系统。产品特色：图形化流程设计、电子印章及手写签名痕迹保留等功能、灵活的工作流处理模式支持、完善的角色权限管理 、严密的安全性管理 、完备的二次开发特性。"
    website "http://www.haitiansoft.com"
    
    matches [

    # Default text
    # intext:技术支持：北京联杰海天科技有限公司
    { :text=>'href="http://www.haitiansoft.com"'  },

    # Version detection

    ]

    end
    