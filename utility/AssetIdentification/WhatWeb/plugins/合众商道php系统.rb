# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "合众商道php系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "合众商道一款PHP建站系统。"
    website "http://www.myhezhong.com/"
    
    matches [

    # Default text
    { :text=>'href="http://www.myhezhong.com"'  },

    # Version detection

    ]

    end
    