# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "弘智房产管理系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "武汉弘智科技房产管理系统是由武汉弘智科技打造的一款房产管理维护一体化系统。"
    website "Unknown"
    
    matches [

    # Default text
    { :text=>'src="images/footright.gif"' },
    { :text=>"027-87299991" }

    # Version detection

    ]

    end
    