# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "天天团购" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "天天团购系统是一套持续6年更新的PHP开源团购程序。"
    website "http://www.tttuangou.com/"
    
    matches [

    # Default text
    { :text=>'Powered by <a href="http://www.tttuangou.com/"'  },
    { :version=>/V([\d\.]+) &copy; 2005 - 2018/  },

    # Version detection

    ]

    end
    