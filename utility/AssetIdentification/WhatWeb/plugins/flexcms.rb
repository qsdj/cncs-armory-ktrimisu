##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FlexCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "FlexCMS is a user-friendly website content management system.  With FlexCMS you can easily build dynamic websites within a matter of minutes with just the click of your mouse!  Maintain your web content, navigation and even limit what groups or specific users can access, from anywhere in the world with just a web browser!  With an emphasis on security and functionality, FlexCMS is a professional and robust system suitable for any business or organization website.  Built on the PHP programming language and the MySQL database, FlexCMS delivers superb performance on any size website."
    website "http://www.flexcms.com/"

    matches [
        {:text=>'<a href="http://www.flexcms.com" target="_blank" class="FooterColors">FlexCMS</a>'},
        {:version=>/<meta name="Generator" content="FlexCMS (v.+)">/}
    
    ]
    
end