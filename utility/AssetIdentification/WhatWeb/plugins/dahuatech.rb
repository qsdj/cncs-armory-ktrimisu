# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "Dahuatech" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "浙江大华技术股份有限公司"
    website "https://www.dahuatech.com/"
    
    # Matches #
    matches [
    
    # url exists, i.e. returns HTTP status 200
    {:regexp=>/var STATIC_URL  = "https?:\/\/www.dahuatech.com\/bocweb\/" ;/},
    {:regexp=>/var UPLOAD_URL  = "https?:\/\/www.dahuatech.com\/upload\/" ;/},
    ]
    
    end