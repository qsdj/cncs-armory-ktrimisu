# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "ZZCMS" do
    author "hyhm2n"
    version "0.1"
    description "ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。"
    website "http://www.zzcms.net/"
    
    
    # Matches #
    matches [
    { :regexp=>/\s*\S*zzcms\s*\S*/},
    { :text=>'<a target="blank" href="http://wpa.qq.com/msgrd?v=1&amp;uin=357856668&amp;Site=zzcms&amp;Menu=yes">'},
    { :text=>'<img border="0" src="http://wpa.qq.com/pa?p=1:357856668:4"'}
    ]
end