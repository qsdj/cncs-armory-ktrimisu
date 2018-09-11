##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "NiubiCMS" do
    author "hyhm2n" # 2010-09-04
    version "0.1"
    description "牛逼CMS 地方门户网站源码系统 PHP免费版。功能包含：新闻、房产、人才、汽车、二手、分类信息、交友、商城、团购、知道、论坛、DM读报、优惠券、本地商家、商家名片等功能。"
    website "http://www.niubicms.com/forum.php"
    
    # 84 results for "powered by Mysource matrix" @ 2010-09-04
    
    # Dorks #
    dorks [
    '"powered by NiubiCMS"'
    ]
    
    
    
    matches [
    
    # Powered by text
    { :text=>'<br>Powered By <a href="http://www.niubicms.com/" target="_blank">niubicms</a> V1.8' },
    { :version=>/<meta name="generator" content="niubicms (V.+)">/}
    ]
end