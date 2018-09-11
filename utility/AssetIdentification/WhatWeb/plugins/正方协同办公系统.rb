# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "正方协同办公系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "协同办公系统的设计目标是帮助各部门快速构建起一个安全、可靠、易用的文档一体化办公环境，实现公文处理的自动化，同时作为内部通讯和信息共享的平台。"
    website "http://www.zfsoft.com"
    
    matches [

    # Default text
    { :text=>'href="http://www.zfsoft.com"' },

    # Version detection

    ]

    end
    