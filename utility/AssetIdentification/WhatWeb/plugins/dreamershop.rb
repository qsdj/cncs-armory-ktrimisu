# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Dreamershop(梦想家网店系统)" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "DreamerShop网店提供了关于零售和批发行业在互联网上进行销售的综合解决方案，通过这个系统，网商们可以迅速、安全的搭建起自己的网上销售商店，开始商务之路。"
    website "https://www.dreamershop.com/"
    
    # Matches #
    matches [
        { :text=>"Dreamershop.com"},
        { :text=>"<meta content=\"DreamerShop,"},
    ]
    
    end