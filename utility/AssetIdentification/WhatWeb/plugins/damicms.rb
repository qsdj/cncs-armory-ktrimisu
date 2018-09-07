# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "DamiCMS(大米CMS)" do
    author "hyhm2n <admin@imipy.com>" # 2014-06-30
    version "0.1"
    description "大米CMS(又名3gcms)是一个免费开源、快速、简单的PC建站和手机建站集成一体化系统， 我们致力于为用户提供简单、快捷的PC建站和智能手机建站解决方案。"
    website "http://www.damicms.com/"
    
    # Matches #
    matches [
        { :text=>'content="damicms"'},
    ]
    
    end