##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "TaoCMS" do
    author "hyhm2n"
    version "0.1"
    description "TaoCMS是一个完善支持多数据库(Sqlite/Mysql)的CMS网站内容管理系统，是国内最小巧的功能完善的基于 php+SQLite/php+Mysql的CMS。体积小速度快，所有的css、JavaScript均为手写代码，无任何垃圾代码，采用严格的数据过滤，保证服务器的安全稳定。"
    website "http://www.taocms.org/"
    
    
    # Matches #
    matches [
    { :text=>'<link rel="stylesheet" href="./template/taoCMS/images/style.css" type="text/css">'},
    { :text=>'<script src="./template/taoCMS/images/tao.js" language="javascript"></script>'},
    { :text=>'Powered By <a href="http://www.taocms.org/" target="_blank">taoCMS</a>'}
    ]
end