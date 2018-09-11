##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "PHPMyWind" do
    author "hyhm2n"
    version "0.1"
    description "PHPMyWind 是一款基于PHP+MySQL开发，符合W3C标准的建站引擎。"
    website "http://www.phpdisk.com/"
    # Matches #
    matches [
        {:text=>'<meta name="generator" content="PHPMyWind CMS">'},
        {:regexp=>/<div class="footer">Copyright \s*\S* phpMyWind.com All Rights Reserved<br>/},
        {:text=>'<a href="http://phpmywind.com" target="_blank">PHPMyWind</a>'}
    ]
end
