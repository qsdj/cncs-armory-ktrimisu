##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "OurPHP(傲派软件)" do
    author "hyhm2n"
    version "0.1"
    description "OURPHP是一个品牌,一款基于PHP+MySQL开发符合W3C标准的建站系统。"
    website "http://www.ourphp.net"
    # Matches #
    matches [
        {:text=>'<meta name="Author" content="www.ourphp.net">'},
        {:version=>/<p>Powered by <a href="http:\/\/www.ourphp.net" target="_blank">www\.Ourphp\.net<\/a>&nbsp;v(.+)&nbsp;<\/p>/}
    ]
end