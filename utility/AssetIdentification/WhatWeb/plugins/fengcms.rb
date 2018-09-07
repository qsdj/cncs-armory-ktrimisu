##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FengCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "FengCms是由地方网络工作室完全知识产权打造的一套适用于个人、企业建站的内容管理系统。"
    website "http://www.fengcms.com/"

    matches [
        { :text=>'<meta name="generator" content="FengCms">'},
        { :text=>'<meta name="author" content="FengCms">'},
        { :version=>/FengCms Beta (.+)/}
    
    ]
    
end