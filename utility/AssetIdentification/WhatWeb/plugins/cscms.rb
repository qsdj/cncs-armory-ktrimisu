# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "CsCMS" do
    author "hyhm2n <admin@imipy.com>" # 20180901
    version "0.1"
    description "程氏CMS专门为中小站长解决建站难的问题、一键采集、一键生成静态、一键安装,傻瓜式的建站程序。"
    website "https://github.com/chshcms/cscms.git"
    
    matches [
        {:text=>"var cscms_path="},
        {:url=>"/cscms/cscms/pay/wxpay/log.php"},
        {:url=>"/cscms/robots.txt", :text=>"CSCMS"}
    ]
    
    end