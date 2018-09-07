##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "FeiFeiCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "飞飞CMS又名飞飞PHP影视系统,包括有PHP版(ppvod)与ASP版(adncms),飞飞CMS由飞飞老谭独立开发,免费提供给站长使用,最大亮点是一键采集海量影视资源!"
    website "http://www.feifeicms.com/"

    matches [
        { :regexp=>/var\s*cms\s*=\s*{\s*root:".*?",urlhtml:".*?",sid:".*?",id:".*?",userid:".*?",username:".*?",userforum:".*?",page:".*?",domain_m:".*?"\s*};/},
        { :text=>'id="navbar-feifeicms"'},
        { :version=>/<a href="http:\/\/www.feifeicms.com\/" target="_blank">feifeicms (.+)<\/a>/}
    
    ]
    
end