##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 by Andrew Horton
## added org.apache.struts.action. seen in stack traces and GET/POST request parameter names

Plugin.define "OTCMS" do
    author "hyhm2n"
    version "0.1"
    description "网钛CMS(OTCMS) PHP版 基于PHP+sqlite/mysql的技术架构，UTF-8编码，以简单、实用、傻瓜式操作而闻名，无论在功能，人性化，还是易用性方面，都有了长足的发展，网钛CMS的主要目标用户锁定在中小型网站站长，让那些对网络不是很熟悉，对网站建设不是很懂又想做网站的人可以很快搭建起一个功能实用又强大，操作人性又易用。"
    website "http://otcms.com/"
    
    
    # Matches #
    matches [

        {:text=>'class="site_{otcms:$webTypeName}'},
        {:text=>'src="cache/js/OTca.js'}
    ]
end