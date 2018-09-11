# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "百奥知实验室综合信息管理系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "BioKnow-LIMS （实验室信息管理系统）能够帮助研究人员与实验室管理者从复杂繁琐又无序的状态下解放出来。系统从实验室综合信息管理的核心部分，包括试剂耗材管理、设备全面管理、项目全面管理、实验对象管理、客户关系管理等多项信息管理职能入手，建立一套适用于各类型生物医药实验室的实验室综合信息管理系统，支持对不同类型单位的业务扩展和全面信息化，满足各大实验机构在信息管理上的迫切需求。实现对各类型实验室资源的有效管理、对课题的全程跟踪以及对科研经费和数据的掌控分析，为实验室研究人员服务。"
    website "http://bioknow.com/"
    
    matches [

    # Default text
    { :text=>'href="http://bioknow.com/"'  },

    # Version detection

    ]

    end
    