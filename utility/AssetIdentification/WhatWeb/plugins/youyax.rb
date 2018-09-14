# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "YouYaX" do
    author "hyhm2n"
    version "0.1"
    description "YouYaX是用PHP语言编写的一套通用论坛系统。秉承简洁实用的设计原则，将传统论坛中一些复杂臃肿的部分统统去掉，保留论坛交流的本质核心，拥有自己独特的原创风格和特性，并且在不断优化和改进。"
    website "http://www.youyax.com"
    
    
    # Matches #
    matches [
    { :text=>'Powered BY YouYaX'}
    ]
end