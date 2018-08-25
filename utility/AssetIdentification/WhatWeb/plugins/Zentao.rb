Plugin.define "Zentao" do
    author "orange <clinlee.me@gmail.com>"
    description "Zentao."
    website "http://www.zentao.net/"
    
    # This is the matches array. 
    # Each match is treated independently.
    
    # Matches #
    matches [
    
    # This searches for a text string.
    { :text => '/zentao/favicon.ico' },
    
    # This searches for a regular expression. Note that the slashes are escaped.
    { :regexp => /zh-cn.default.css\?v=/ },
    
    { :version => /zh-cn.default.css\?v=(.*?)' type=/ }, 
    
    ] 
    
    end