# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "WuZhiCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "WUZHI CMS是中国五指（WUZHI）互联科技公司的一套基于PHP和MySQL的开源内容管理系统（CMS）。"
    website "https://www.wuzhicms.com/"
    
    # Matches #
  matches [
      
        {:text=>'index.php?m=member&v=logout'},

        # url exists, i.e. returns HTTP status 200
        {:url=>"/index.php?m=core&v=login&_su=wuzhicms",:text=>"wuzhicms.com"},
        {:url=>"/coreframe/"},
        {:url=>"/robots.txt",:text=>"coreframe"},
        ]
        
            
    end
    
