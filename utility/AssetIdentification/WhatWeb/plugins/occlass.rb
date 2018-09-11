##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "OSClass" do
    author "hyhm2n"
    version "0.1"
    description "osclass是一个开源项目，允许您在没有任何技术知识的情况下轻松创建分类网站。"
    website "http://osclass.org/"
    
    
    # Matches #
    matches [

        {:text=>'<div>This website is proudly using the <a title="Osclass web" href="http://osclass.org/">classifieds scripts</a> software <strong>Osclass</strong></div>'},
        {:version=>/<meta name="generator" content="Osclass (.+)">/}
    ]
end