# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "BaijiaCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "BaijiaCMS是一套用于电子商务的内容管理系统（CMS）。"
    website "https://github.com/baijiacms/baijiacmsV3"
    
    # Matches #
  matches [
           
          {:text=>'index.php?mod=mobile&name=public&do=login'},
          {:text=>'/assets//addons/public/login/001.jpg'},
          ]
        
    end
    
