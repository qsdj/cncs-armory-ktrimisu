# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "DaMall" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "DaMall商城系统。"
    website "https://www.damall.cn/"
    
    # Matches #
    matches [
    
    # url exists, i.e. returns HTTP status 200
    {:text=>"static.damall.cn"},
    {:text=>"www.damall.cn"},
    ]
    
    end