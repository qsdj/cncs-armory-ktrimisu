##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "chanzhiEPS(蝉知门户系统)" do
    author "hyhm2n"
    version "0.1"
    description "蝉知门户系统(chanzhiEPS)是一款开源免费的企业门户系统,企业建站系统,CMS系统。"
    website "http://www.chanzhi.org/"
    
    
    # Matches #
    matches [
    { :regexp=>/<div id="powerby">\s*<a href="http:\/\/www.chanzhi.org\/?v=(.+)"/},
    { :regexp=>/<span class="icon-chanzhi"><\/span> <span class="name">\S*<\/span>(.+)<\/a>/},
    { :version=>/<meta name="Generator" content="chanzhi(.+) www.chanzhi.org'">/}
    ]
end