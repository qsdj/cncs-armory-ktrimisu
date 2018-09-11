# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "方正Apabi数字资源平台" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "北京方正阿帕比技术有限公司是北大方正信息产业集团有限公司旗下专业的数字出版技术及产品提供商。方正阿帕比公司自2001年起进入数字出版领域，在继承并发展方正传统出版印刷技术优势的基础上，自主研发了数字出版技术及整体解决方案，已发展成为全球领先的数字出版技术提供商。"
    website "http://www.apabi.cn/"
    
    matches [

    # Default text
    # inurl:List.asp?lang=gb inurl:DocID
    { :md5=>"d0ff6bd510980ac5779099702feee304", :url=>'images/professional/gb/zin01.gif' },
    { :text=>"Founder Apabi Statement" },
    { :text=>"Apabi(" },

    # Version detection

    ]

    end
    