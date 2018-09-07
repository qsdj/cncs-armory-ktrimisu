##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "HiShop易分销系统" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "HiShop是国内领先的商城系统及微分销系统与新零售系统提供商.为企业提供新零售系统,微分销系统,网上商城系统,B2B2C商城系统,多用户商城系统,分销小程序商城系统。"
    website "https://www.hishop.com.cn"

    matches [
        {:text=>'<div id="hishop_wx" style="display: none;">'},
        {:text=>'o=www.hishop.com.cn&amp;'}


    ]
    
end