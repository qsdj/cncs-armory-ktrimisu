##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "WeCenter" do
    author "hyhm2n"
    version "0.1"
    description "Wecenter(微中心系统软件)是一款由深圳市微客互动有限公司开发的具有完全自主知识产权的开源软件。"
    website "http://www.wecenter.com/"
    
    
    # Matches #
    matches [
    { :regexp=>/<script src="https?:(\s*\S*)\/static\/js\/roll\/assets\/js\/slider.js"><\/script>/},
    { :regexp=>/<div class="aw-footer">\s*\S*Copyright\s*\S*,All Rights Reserved\s*\S*<span class="hidden-xs">\s*\S*Powered By\s*\S*<a href="\/" target="blank">WeCenter\s*\S*<\/a><\/span>\s*\S*<\/div>/},
    ]
end