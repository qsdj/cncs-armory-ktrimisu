# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "天生创想OA" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "天生创想OA是由北京天生创想信息技术有限公司自公司打造的一款办公管理系统。"
    website "http://www.515158.com/"
    
    matches [

    # Default text
    { :text=>'Powered by <a href="http://www.515158.com/">'  },
    { :version=>/OA<\/a> V([\d\.]+)<\/div>/ },

    # Version detection

    ]

    end
    