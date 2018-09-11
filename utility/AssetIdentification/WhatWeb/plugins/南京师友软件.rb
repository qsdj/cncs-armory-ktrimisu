# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "南京师友软件" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "南京师友软件是一个网站集群管理系统"
    website "http://www.edu025.net/"
    
    matches [

    # Default text
    { :text=>'<a href="/webSchool/default.aspx">' },
    { :text=>'<a href="/webTeacher/default.aspx">' },
    { :text=>'<a href="/webManage/default.aspx">' },
    { :text=>'<a href="webResource/default.aspx">' },

    # Version detection

    ]

    end
    