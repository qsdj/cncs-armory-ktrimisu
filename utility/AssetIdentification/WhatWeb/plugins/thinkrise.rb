##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "TinyRise" do
    author "hyhm2n"
    version "0.1"
    description "TinyRise是一款B2C独立网店系统,适合企业及个人快速构建个性化网上商店。"
    website "http://www.tinyrise.com/"
    
    
    # Matches #
    matches [
    { :text=>'<link rel="shortcut icon" href="/tinyshop/favicon.ico">'},
    { :regexp=>/Powered\s*by\s*TinyRise/},
    { :regexp=>/Powered by TinyShop\s*\S*tinyrise\.com\s*\S*/}
    
    ]
end