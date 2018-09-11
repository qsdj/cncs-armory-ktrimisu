##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "QCMS" do
    author "hyhm2n"
    version "0.1"
    description "QCMS是一套开源的用于创建响应式网站的内容管理系统（CMS）。"
    website "http://www.q-cms.cn"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :version=>/<a href="http:\/\/www.q-cms.cn" target="_blank">QCMS.* (.+)<\/a>/ }
    
    ]
    
    end