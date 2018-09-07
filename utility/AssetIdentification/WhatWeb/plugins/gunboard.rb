##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "GNUboard" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "Gnuboard是韩国Sir公司开发一套PHP+Mysql可扩展论坛程序。将主程序与Skin（风格文件）完全剥离，通过skin的编辑可以制作人才就业网站、房产信息平台、供求信息发布、甚至可以作为企业产品展示。"
    website "https://gnuboard.com/"

    matches [
        {:regexp=>/<meta name="description" content="SIR, SIRSOFT, .*?, GNUBOARD Multi Language, GNUBOARDM">/},
        {:text=>"var gml_bbs_url"},
        {:text=>"var gml_bo_table"},
        {:text=>'var gml_lang = "ko_KR";'},
    ]
    
end