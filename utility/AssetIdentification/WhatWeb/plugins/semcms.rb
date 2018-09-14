##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "SEMCMS" do
    author "hyhm2n"
    version "0.1"
    description "SemCms是一套开源外贸企业网站管理系统,主要用于外贸企业,兼容IE、Firefox 、google、360 等主流浏览器。"
    website "http://www.sem-cms.com"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :regexp=>/<div class="sc_bot_3">CopyRight\s*\S*semcms<script type="text\/javascript" src="https:\/\/js.users.51.la\/19397399.js"><\/script>/},
    { :version=>/Powered by <a href="http:\/\/www.sem-cms.com"><b style="color:#F60">semcms PHP (.*)<\/b><\/a>/ }
    
    ]
    
    end