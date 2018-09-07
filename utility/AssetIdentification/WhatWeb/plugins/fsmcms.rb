##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FSMCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "FSMCMS是北京东方文辉信息技术有限公司开发的一套内容管理系统。"
    website "http://www.bjdfwh.com.cn/"

    matches [
        { :regexp=>/COPYRIGHT .*? BJDFWH.COM.CN/},
        { :text=>'Email :cms@fsmcms.com.cn'},

    
    ]
    
end