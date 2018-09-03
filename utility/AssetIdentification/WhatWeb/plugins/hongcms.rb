# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "HongCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "HongCMS中英文网站系统是一个轻量级的网站系统，访问速度极快，使用简单。程序代码简洁严谨，完全免费开源。 可用于建设各种类型的中英文网站，同时它是一个小型开发框架。"
    website "https://github.com/Neeke/HongCMS"
    
    # Matches #
  matches [
           
        {:text=>'/public/templates/Default/images/'},
        {:text=>'vP2uJFhaBC3Tlang'},

        # url exists, i.e. returns HTTP status 200
        {:url=>"/includes/index.html",:text=>'Directory access is forbidden'},
        {:url=>"/admin/controllers/editor_file_manager.php"},
        ]
        
            
    end
    
