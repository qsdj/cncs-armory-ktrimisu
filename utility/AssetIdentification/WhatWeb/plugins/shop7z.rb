##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Shop7z" do
    author "hyhm2n"
    version "0.1"
    description "Shop7z网上购物系统是国内优秀的网上开店软件，模板新颖独特，功能强大，自主知识产权国家认证，数万用户网上开店首选，可以快速建立自己的网上商城。"
    website "http://www.shop7z.com/"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :regexp=>/<span style="font-size:14px;">Shop7z\s*\S*COPYRIGHT\s*\S*Shop7z.COM ALL RIGHTS RESRVED\s*<\/span>/},
    { :text=>"div class=\"Shop7z_kefu\">"}
    
    ]
end