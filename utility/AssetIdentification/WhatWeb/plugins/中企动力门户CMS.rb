# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "中企动力门户CMS" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "中企动力门户CMS是一个内容管理系统。"
    website "http://www.sino-i.com/"
    
    matches [

    # Default text
    { :text=>"中企动力" },
    { :text=>'membersarticleCategoryId' },
    { :url=>'membersarticleCategoryId' },

    # Version detection

    ]
    
    end
    