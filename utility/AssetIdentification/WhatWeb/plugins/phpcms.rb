##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "PHPCMS" do
    author "shang <s@suu.cc>" # 2014-08-15
    version "0.1.2"
    description "phpCMS [Chinese] - Homepage: http://www.phpcms.cn/"
    
    # Dorks #
    dorks [
    '"Powered By phpCMS"'
    ]
    
    # Matches #
    matches [
    
      # url exists, i.e. returns HTTP status 200
      {:text=>"<meta name=\"phpCMS.robots"},
      {:text=>"<!-- PHPCMS_NOINDEX"},
      {:url=>"/statics/css/default_blue.css",:version=>/images\/v([\d\.]+)\/body-bg.png/},#php9
      {:text=>"/statics/css/default_blue.css"},
      {:version=>/blank\">Powered by Phpcms ([\d\.]+)</},#php 2008 
      {:version=>/strong> <em>V([\d\.]+)</},#php 9.1.13,9.2.7
      {:version=>/<meta name=\"generator\" content=\"Phpcms ([\d\.]+)\">/} #php 2007
      
    ]
    
    
    end