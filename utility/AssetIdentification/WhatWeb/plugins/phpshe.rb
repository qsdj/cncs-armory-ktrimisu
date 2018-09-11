##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "PHPShe" do
    author "hyhm2n"
    version "0.1"
    description "PHPSHE网上商城系统具备电商零售业务所需的所有基本功能,以其安全稳定、简单易用、高效专业等优势赢得了用户的广泛好评,为用户提供了一个低成本、高效率的网上商城服务。"
    website "http://www.phpshe.com"
    # Matches #
    matches [
        {:regexp=>/href="https?:\/\/.*\.?.*\..*\/?.*\/template\/default\/index\/kefu\/css\/style.css">/},
        {:regexp=>/<script type="text\/javascript" src="https?:\/\/.*\..*.\.*\/?.*\/include\/js\/jquery.scrollLoading.js"><\/script>/},
        {:version=>/Powered by <a href="http:\/\/www.phpshe.com" target="_blank" title="PHPSHE.*">phpshe(.+)<\/a>/}
    ]
end
