Plugin.define "Phabricator" do
    author "orange"
    description "Phabricator is an integrated set of powerful tools to help companies build higher quality software."
    website "https://www.phacility.com/"
    
    # This is the matches array. 
    # Each match is treated independently.
    
    # Matches #
    matches [
    
    # This searches for a text string.
    { :text => '<title>Login to Phabricator<\/title>' },
    
    # This searches for a regular expression. Note that the slashes are escaped.
    { :regexp => /<title>Login to Phabricator<\/title>/ },
    
    # This extracts the version of Generic CMS from the Mega generator tag.
    ] 
    
    end