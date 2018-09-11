##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "PHPB2B" do
    author "hyhm2n"
    version "0.1"
    description "友邻B2B网站系统(PHPB2B)是一款基于PHP程序和Mysql数据库、以MVC架构为基础的开源B2B行业门户电子商务网站建站系统，系统代码完整、开源，功能全面，架构优秀，提供良好的用户体验、多国语言化及管理平台，是目前搭建B2B行业门户网站最好的程序。"
    website "http://www.phpb2b.com"
    # Matches #
    matches [
        {:text=>'<meta name="description" content=" phpb2b'},
        {:regexp=>/<p>Powered by PHPB2B .* <a href="http:\/\/www.phpb2b.com\/" target="_blank"><strong>Ualink<\/strong><\/a>/}
    ]
end