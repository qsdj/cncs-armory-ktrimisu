##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "POSCMS" do
    author "hyhm2n"
    version "0.1"
    description "POSCMS（PhpOpenSourceCMS）是中国天睿信息技术公司的一套基于PHP和MySQL的、开源的、跨平台网站内容管理系统（CMS）。"
    website "http://www.poscms.net/"
    # Matches #
    matches [
        {:text=>"(!$.cookie('poscms_qq'))"},
        {:text=>"$.cookie('poscms_qq', '1',{expires: 1});"},
        {:version=>/POSCMS v(.+)/}
    ]
end