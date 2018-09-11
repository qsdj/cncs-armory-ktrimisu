##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "QYKCMS(青云客博客CMS)" do
    author "hyhm2n"
    version "0.1"
    description "青云客网站管理系统简称QYKCMS,是青云客开发的一款基于PHP+MySql的轻量级智能建站系统。"
    website "http://www.qykcms.com/"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :text=>"Powered by <a target=\"_blank\" href=\"http://cms.qingyunke.com\""},
    { :version=>/QYKCMS (.+)<\/a>/ }
    
    ]
    
    end