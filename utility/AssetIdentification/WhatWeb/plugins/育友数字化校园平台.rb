# encoding: utf-8
##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
Plugin.define "育友数字化校园平台" do
    author "47bwy <admin@47bwy.com>" # 20180829
    version "0.1"
    description "杭州育友软件有限公司与浙江皓翰文化发展集团强强联合组建新公司，浙江皓翰科技有限公司。杭州育友软件有限公司，1998年创立于天堂硅谷——杭州，涉及领域涵盖互联网业务、学校软件业务、教育城域网、教育移动增值服务以及教育咨询，业务遍及全国各省，是浙江省科学技术厅认定的高新技术企业。"
    website "http://www.yuysoft.com/"
    
    matches [

    # Default text
    # intext:技术支持:杭州育友软件有限公司
    { :text=>'a href="http://www.yuysoft.com/"' },

    # Version detection

    ]

    end
    