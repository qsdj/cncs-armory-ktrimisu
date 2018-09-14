##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "ShopNum1" do
    author "hyhm2n"
    version "0.1"
    description "ShopNum1网店系统是武汉群翔软件有限公司自主研发的基于 WEB 应用的 B/S 架构的B2C网上商店系统，主要面向中高端客户， 为企业和大中型网商打造优秀的电子商务平台，ShopNum1运行于微软公司的 .NET 平台，采用最新的 ASP.NET 3.5技术进行分层开发。拥有更强的安全性、稳定性、易用性。"
    website "http://www.shopnum1.com/"
    
    
    # Matches #
    matches [
    { :text=>'<a id="shopCopyright_ctl00_HyperLinkUrl" target="_blank"><span id="shopCopyright_ctl00_labelPoweredBy"></span></a>'},
    { :regexp=>/<span id="shopCopyright_ctl00_labelName">ShopNum1\s*\S*<\/span>/},
    { :regexp=>/<span id="shopCopyright_ctl00_labelCopyright"><p>	Copyright @\s*\S*GroupFly. All Rights Reserved.\s*\S*<\/p><\/span>/}
    
    ]
end