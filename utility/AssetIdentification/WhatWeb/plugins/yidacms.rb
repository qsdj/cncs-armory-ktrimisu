# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "YidaCMS(易达CMS)" do
    author "hyhm2n"
    version "0.1"
    description "YidaCMS免费开源网站管理系统，是一款简单、实用、高效的网站建站软件。YidaCMS免费开源网站管理系统是基于微软的WINDOWS IIS平台，采用ASP语言ACCESS和MSSQL双数据库开发完成。\n整体系统采用强大的HTML引擎，模板设计和程序语言完全分开，这会让您在设计模板时更加快捷和方便。全站静态化及标准的URL路径，更加让百度等搜索引擎青睐。"
    website "http://www.yidacms.com"
    
    
    # Matches #
    matches [
    { :text=>'<meta name="Author" content="www.yidacms.com">'},
    { :text=>'<input name="yidacms_search" type="hidden" value="yidacms">'},
    { :regexp=>/<span>E-MAIL\s*\S*ceo@yidacms.com<\/span>/},
    { :text=>'<li class="yidacms_qqtop">'}
    ]
end