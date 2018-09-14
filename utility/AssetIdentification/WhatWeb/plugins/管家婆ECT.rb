# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "管家婆ECT" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "管家婆ECT是任我行软件发展公司推出的进销存、财务一体化软件。"
    website "http://www.wecrm.com"
    
    matches [

    # Default text
    { :text=>'Href = "http://www.wecrm.com"'  },

    # Version detection

    ]

    end
    