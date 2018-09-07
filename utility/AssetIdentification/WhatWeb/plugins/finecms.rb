##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FineCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "FineCMS是一款基于PHP+MySql开发的内容管理系统，采用MVC设计模式实现业务逻辑与表现层的适当分离，使网页设计师能够轻松设计出理想的模板，插件化方式开发功能易用便于扩展，支持自定义内容模型和会员模型，并且可以自定义字段，系统内置文章、图片、下载、房产、商品内容模型，系统表单功能可轻松扩展出留言、报名、书籍等功能，实现与内容模型、会员模型相关联，FineCMS可面向中小型站点提供重量级网站建设解决方案。"
    website "http://demo.finecms.net/"

    matches [
        { :version=>/<span>FineCMS.*? (v.+)<\/span>/}
    
    ]
    
end