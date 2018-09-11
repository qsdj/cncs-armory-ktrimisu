##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "PloneCMS" do
    author "hyhm2n"
    version "0.1"
    description "Plone 是免费的、开放源代码的内容管理系统（Content Management System，CMS）。"
    website "https://plone.org/"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :version=>/<li>Plone (.+) \(.*\)<\/li>/ },
    {:text=>'<meta name="generator" content="Plone - http://plone.com">'}
    
    ]
    
    end