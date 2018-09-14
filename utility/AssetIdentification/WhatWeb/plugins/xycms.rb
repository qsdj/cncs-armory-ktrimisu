##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "XYCMS" do
    author "hyhm2n"
    version "0.1"
    description "XYCMS企业建站系统是以asp+access进行开发的企业建站系统。"
    website "http://www.jsxyidc.com/"
    
    
    # Matches #
    matches [
    { :text=>'<meta name="Author" content="xycms">'},
    { :text=>'<input name="xycms_keys" type="text" class="s_txt" id="search-keyword"'},
    { :text=>'#xycmskf'}
    ]
end