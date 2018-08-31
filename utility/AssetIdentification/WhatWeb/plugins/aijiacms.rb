# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "AiJiaCMS(爱家CMS)" do
    author "hyhm2n <admin@imipy.com>" # 20180829
    version "0.1"
    description "aijiacms 网站系统是基于PHP+MySQL的房产行业门户解决方案。"
    website "http://www.aijiacms.com/"
    
    matches [
    { :text=>"var aijiacms_userid = 0;" },
    {:text=>"var aijiacms_username = '';"},
    {:text=>"var aijiacms_message = 0;"},
    {:text=>"var aijiacms_chat = 0;"},
    {:text=>"var aijiacms_member = '';"},
    ]
    
    end
    