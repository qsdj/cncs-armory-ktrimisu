##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "OpenSNS" do
    author "hyhm2n"
    version "0.1"
    description "OpenSNS开源社交建站系统,是基于OneThink的轻量级社交化用户中心框架。"
    website "http://www.opensns.cn/"
    
    
    # Matches #
    matches [
        {:text=>'<a href="http://www.opensns.cn" target="_blank">Powered by OpenSNS</a>'},
    ]
end