# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "wolfcms" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "启航内容管理系统(DTcms)是国内ASP.NET开源界少见的优秀开源网站管理系统，基于 ASP.NET(C#)+ MSSQL(ACCESS) 的技术开发，开放源代码。使用Webform普通三层架构开发模式，轻量级架构，后台使用原始的开发方式，无任何技术门槛，使得开发人员更容易上手。注重后台管理界面，采用Jquery和CSS3界面设计，兼容IE8及以上主流浏览器响应式后台管理界面，支持电脑、移动设备使用。"
    website "http://www.dtcms.net/"
    
    # Matches #
  matches [
        # url exists, i.e. returns HTTP status 200
        {:name=>"admin/login.aspx",:text=>"ie6update.html"},
        ]
        
            
    end
    
