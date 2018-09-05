# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "万户OA" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。"
    website "http://www.whir.net"
    
    matches [

    # Default text
    { :text=>"whirRootPath" },
    { :text=>"preUrl" },
    { :text=>"whir_browser" },
    { :text=>"whir_agent" },

    # Version detection

    ]
    
    end
    