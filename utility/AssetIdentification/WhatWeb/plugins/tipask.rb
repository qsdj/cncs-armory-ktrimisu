##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Tipask" do
    author "hyhm2n"
    version "0.1"
    description "tipask，即Tipask问答系统，是一款开放源码的PHP仿百度知道程序。"
    website "http://www.tipask.com/"
    
    
    # Matches #
    matches [
    { :version=>/<p>Powered by <a rel="nofollow" target="_blank" href="http:\/\/www.tipask.com\/">Tipask v(.+)<\/a>\s*\S*<a rel="nofollow" target="_blank" href="http:\/\/www.tipask.com">tipask.com<\/a>/},
    { :regexp=>/<meta name="copyright" content=".+? tipask.com">/},
    { :text=>'<meta name="author" content="Tipask Team">'},
    ]
end