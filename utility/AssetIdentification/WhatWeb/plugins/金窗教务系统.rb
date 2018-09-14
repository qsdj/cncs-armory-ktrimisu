# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "金窗教务系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "金窗教务管理系统是为高校数字校园建设提供的技术解决方案。"
    website "http://www.gowinsoft.com/"
    
    matches [

    # Default text
    { :text=>'Powered by <a href="http://www.gowinsoft.com/"'  },
    { :text=>'Gowinsoft Inc.'  },

    # Version detection

    ]

    end
    