##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FlatNuke" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "FlatNuke是一个PHP开发的内容管理系统，无须数据库支持，使用的是文本文件来保存内容。"
    website "http://flatnuke.netsons.org/"

    matches [
        {:regexp=>/<meta name="copyright" content="Copyright \(c\) .* by FlatNuke Home page">/},
        {:text=>'<meta name="description" content="This is my personal website powered by Flatnuke technology">'},
        {:text=>'<img align="middle" border="0" src="images/validate/flatnuke_powered.png" alt="FlatNuke">'},
        {:text=>'<a href="http://www.flatnuke.org/" target="_blank" title="FlatNuke">'}
    
    ]
    
end