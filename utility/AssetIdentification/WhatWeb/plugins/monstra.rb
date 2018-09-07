##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# http://www.morningstarsecurity.com/research/whatweb
##
# Version 0.2 # 2011-01-10 #
# Updated version detection
##
Plugin.define "MonstraCMS" do
    author "hyhm2n <admin@imipy.com>" # 2010-09-18
    version "0.1"
    description "Monstra is a content management system (CMS) written for server environments where a database is just too much to handle and/or is inaccessible."
    website "https://github.com/monstra-cms/monstra"

    matches [
        {:text=>'<meta name="generator" content="Powered by Monstra">'},
        {:text=>'Powered by <a href="http://monstra.org" target="_blank">Monstra</a>'},
        {:version=>/content="Powered by Monstra (.+)"/}     
    ]
    
end