##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "JeeCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "JEECMS是国内Java版开源网站内容管理系统（java cms、jsp cms）的简称。"
    website "http://www.jeecms.com"

    matches [
        {:text=>'Powered by JeeCms'}
    
    ]
    
end