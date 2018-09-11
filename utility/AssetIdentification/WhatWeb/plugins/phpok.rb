##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "PHPOK" do
    author "hyhm2n"
    version "0.1"
    description "PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。"
    website "https://www.phpok.com/"
    # Matches #
    matches [
        {:text=>"$.phpok.json(api_url('task'),function(rs){return true;});"},

        {:regexp=>/Powered By phpok.com\s*\S*, All right reserved./},
        {:text=>'<li><i class="am-icon-at am-icon-fw"></i> admin@phpok.com</li>'}
    ]
end
