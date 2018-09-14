##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "ShopNC" do
    author "hyhm2n"
    version "0.1"
    description "ShopNC商城系统，是天津市网城天创科技有限责任公司开发的一套多店模式的商城系统。"
    website "http://www.shopnc.net"
    
    
    # Matches #
    matches [
    { :text=>'<meta name="copyright" content="ShopNC Inc. All Rights Reserved">'},
    { :text=>'<meta name="author" content="ShopNC">'},
    { :text=>'Powered by <a href="http://www.shopnc.net" target="_blank"><span class="vol"><font class="b">Shop</font><font class="o">NC</font></span></a>'}
    
    ]
end