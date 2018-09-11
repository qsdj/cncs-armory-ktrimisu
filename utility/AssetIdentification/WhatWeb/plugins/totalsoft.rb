# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "totalsoft" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "totalsof整个系统采用国际流行的Browser / WebServer / DBServer 三层或 Client / Server 双层体系结构， 后台选用大型关系数据库Sql Server 2000 作为系统平台（并全面支持Sybase和Oracle数据库）。"
    website "http://www.totalsoft.com.cn/"
    
    matches [

    # Default text
    { :text=>"RDSuggestBook.aspx" },
    { :url=>"/RDSuggestBook.aspx" },

    # Version detection

    ]

    end
    