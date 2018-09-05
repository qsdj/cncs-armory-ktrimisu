# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "上海鼎创通用型数字校园系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "上海鼎创通用型数字校园系统。"
    website "http://www.goodo-edu.com/"
    
    matches [

    # Default text
    { :text=>'<a href="http://www.goodo.com.cn" target="_blank" style="text-decoration:none;">' },
    { :text=>"EduPlate"}

    # Version detection

    ]
    
    end
    