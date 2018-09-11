# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "乾豪综合教务管理系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "大连乾豪综合教务管理系统致力于高校信息化软件的研究与开发。目前在高校信息化方面已经形成了一套完整的信息化解决方案，本方案的目标是整合高校的管理数据和教学资源。"
    website "http://www.tsanghao.com/"
    
    matches [

    # Default text
    { :url=>"ACTIONSHOWNEWS"  },
    { :text=>'href="ACTIONSHOWNEWS' },

    # Version detection

    ]

    end
    