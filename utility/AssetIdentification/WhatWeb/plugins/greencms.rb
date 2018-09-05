# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "GreenCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "GreenCMS是一套基于ThinkPHP开发的内容管理系统（CMS）。"
    website "https://github.com/GreenCMS/GreenCMS"
    
    # Matches #
  matches [
           
        {:text=>'/Public/NovaGreenStudio/css/bootstrap-responsive.min.css'},
        {:text=>'/Public/NovaGreenStudio/css/main.css'},
        {:text=>'/Public/NovaGreenStudio/css/sl-slide.css'},
        {:text=>'/index.php?m=&c=form&a=apply'},

        # url exists, i.e. returns HTTP status 200
        {:url=>"/composer.json",:text=>'GreenCMS'},
        {:url=>"/robots.txt",:text=>'GreenCMS'},
        ]
        
            
    end
    
