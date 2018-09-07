# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "DiliCMS" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "DiliCMS，一个基于CodeIgniter的快速开发内容管理系统。"
    website "http://www.dilicms.com/"
    
    # Matches #
    matches [
        { :text=>"DiliCMS"},
        { :url=>"/README.md", :regexp=>/[DiliCMS](http:\/\/www.dilicms.com)/},
    ]
    
    end