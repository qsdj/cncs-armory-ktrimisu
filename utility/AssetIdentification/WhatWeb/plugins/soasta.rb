Plugin.define "Soasta" do
    author "orange"
    description "CloudTest makes it easy to test to any level of expected usage – and beyond. "
    website "https://www.soasta.com"
    
    # This is the matches array. 
    # Each match is treated independently.
    
    # Matches #
    matches [
    
    # This searches for a text string.
    { :text => 'SOASTA' },
    
    # This searches for a regular expression. Note that the slashes are escaped.
    { :regexp =>/loginButton.png?version">/ },
    
    { :version => /<meta name="buildnumber" content="(.*?)">/ }, 
    
    ] 
    
    end