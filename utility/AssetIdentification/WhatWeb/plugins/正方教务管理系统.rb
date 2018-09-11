# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "正方教务管理系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "正方现代教学管理系统是一个面向学院各部门以及各层次用户的多模块综合信息管理系，包括教务公共信息维护、学生管理、师资管理、教学计划管理、智能排课、考试管理、选课管理、成绩管理、教材管理、实践管理、收费管理、教学质量评价、毕业生管理、体育管理、实验室管理以及学生综合信息查询、教师网上成绩录入等模块，能够满足从学生入学到毕业全过程及教务管理各个环节的管理需要。系统采用了当前流行的C/S结构和Internet网络技术，使整个校园网甚至Internet上的用户都可访问该系统，最大程度地实现了数据共享，深受广大用户青睐。"
    website "http://www.zfsoft.com"
    
    matches [

    # Default text
    { :text=>'href="http://www.zfsoft.com"' },

    # Version detection

    ]

    end
    