##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "ThinkSAAS" do
    author "hyhm2n"
    version "0.1"
    description "ThinkSAAS开源社区基于PHP+MySQL开发完成，运行于Linux 平台和Windows平台，完美支持Apache和Nginx运行环境。"
    website "https://www.thinksaas.cn"
    
    
    # Matches #
    matches [
    { :text=>'<meta name="Copyright" content="ThinkSAAS">'},
    { :text=>'<meta name="author" content="qiujun@thinksaas.cn">'},
    { :regexp=>/<a target="_blank" class="text-secondary" title="\s*\S*" href="https:\/\/www.thinksaas.cn\/">ThinkSAAS<\/a>/}
    
    ]
end