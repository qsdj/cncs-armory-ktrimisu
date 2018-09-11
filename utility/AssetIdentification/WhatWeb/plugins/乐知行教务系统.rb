# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "乐知行教务系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "乐知行教学系统是北京讯飞乐知行软件有限公司打造的一款教学管理一体化系统。"
    website "http://www.lezhixing.com.cn/"
    
    matches [

    # Default text
    { :text=>'<span class="dl_user"><input name="" id="username" type="text"  class="dl_input"/></span>' },

    # Version detection

    ]
    
    end
    