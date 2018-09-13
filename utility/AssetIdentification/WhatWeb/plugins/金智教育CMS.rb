# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "金智教育CMS" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "金智教育是中国最大的教育信息化服务提供商。金智教育专注于教育信息化领域，致力于成为中国教育信息化服务的领航者，成为业界最具吸引力的事业平台，以通过信息化促进教育公平。"
    website "http://www.wisedu.com/"
    
    matches [

    # Default text
    { :text=>'href="http://www.wisedu.com/"'  },

    # Version detection

    ]

    end
    