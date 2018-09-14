##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "TRS-IDS(拓尔思身份服务器系统)" do
    author "hyhm2n"
    version "0.1"
    description "拓尔思身份服务器系统实现各种应用系统间跨域的单点登录和统一的身份管理功能。提供与第三方协作应用系统集成的框架以及非常便捷的二次开发接口。"
    website "http://www.trs.com.cn/"
    
    
    # Matches #
    matches [
    
    # Meta generator
    { :text=>'<script language="JavaScript" src="js/IdSUtil.js"></script>'},
    { :regexp=>/TRS\s*\S* TRSIDS/},
    { :text=>'<input type="hidden" name="sourceName" value="ids_internal">'}
    
    ]
end