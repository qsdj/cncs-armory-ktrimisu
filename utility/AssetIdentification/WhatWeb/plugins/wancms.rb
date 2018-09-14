##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "WanCMS" do
    author "hyhm2n"
    version "0.1"
    description "wancms 程序,全开源不加密,php+mysql,提供手册,便于二次开发.后台操作简单,功能强大。"
    website ""
    
    
    # Matches #
    matches [
    { :regexp=>/<link rel="stylesheet" type="text\/css" href="(\/wancms)?\/public\/Phonegame\/css\/youxi.css">/},
    { :regexp=>/url:"(\/wancms)?\/index.php?g=&m=Game&a=history"/},
    ]
end