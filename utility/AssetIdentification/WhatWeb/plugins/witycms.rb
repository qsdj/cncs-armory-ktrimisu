# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "wityCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "wityCMS是一套基于PHP的面向模型-视图-控制器的轻量级内容管理系统（CMS）。"
    website "https://github.com/Creatiwity/wityCMS"
    
    # Matches #
  matches [
           
        {:text=>'/themes/grafx/img/button-plus.png'},
        {:text=>'witycms/themes.plugin'},

        # url exists, i.e. returns HTTP status 200
        {:url=>"/libraries/witycms/admin.js",:text=>"wityCMS"},
        ]
        
            
    end
    
