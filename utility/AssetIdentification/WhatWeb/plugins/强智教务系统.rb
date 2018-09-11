# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "强智教务系统" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "强智教务系统是由湖南强智科技发展有限公司打造的一款中和教务服务系统。"
    website "http://www.qzdatasoft.com"
    
    matches [

    # Default text
    # powered by 强智科技
    { :text=>'href="http://www.qzdatasoft.com"'  },

    # Version detection

    ]

    end
    