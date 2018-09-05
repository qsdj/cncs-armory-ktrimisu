# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "SEACMS(海洋CMS)" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。"
    website "http://www.seacms.net/"
    
    # Matches #
  matches [
           
        {:text=>'http://www.seacms.net'},

        # url exists, i.e. returns HTTP status 200
        {:url=>"/data/mark/inc_photowatermark_config.php"},
        {:url=>"/zyapi.php"},
        {:url=>"/include/inc/inc_fun_funAdmin.php",:text=>"Request Error!"},
        ]
        
            
    end
    
