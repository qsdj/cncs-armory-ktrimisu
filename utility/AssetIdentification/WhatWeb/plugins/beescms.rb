# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "BEESCMS" do
    author "国光 <admin@sqlsec.com>" #20180901
    version "0.1"
    description "BEESCMS企业网站管理系统是一款PHP+MYSQL的多语言系统，内容模块易扩展，模板风格多样化，模板制作简单功能强大，专业SEO优化，后台操作方便，完全可以满足企业网站、外贸网站、事业单位、教育机构、个人网站使用。"
    website "http://www.beescms.com/"
    
    # Matches #
  matches [
           
           {:text=>'/template/default/images/search_btn.gif'},
           {:text=>'/upload/img/20110625/201106251133539086.gif'},
           {:text=>'http://www.beescms.com'},
     
           # url exists, i.e. returns HTTP status 200
           {:url=>"/data/compile_tpl/member_login_cn_compile.php"},       
          ]
        
    end
    
