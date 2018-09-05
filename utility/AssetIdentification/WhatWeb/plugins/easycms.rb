# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "EasyCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "EasyCMS是一套使用PHP语言编写的、轻量级可扩展的开源内容管理系统（CMS）。"
    website "http://www.easycms.cc/"
    
    # Matches #
  matches [
           
        {:text=>'/index.php?s=/index/article/checkuser.html'},
        # url exists, i.e. returns HTTP status 200
        {:url=>"/App/Modules/Admin/Model/UserRelationModel.class.php",:text=>'\App\Modules\Admin\Model\UserRelationModel.class.php'},
        ]
        
            
    end
    
