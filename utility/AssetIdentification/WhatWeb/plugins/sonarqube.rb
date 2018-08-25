Plugin.define "SonarQube" do
    author "orange"
    description "SonarQube is an open source quality management platform, dedicated to continuously analyze and measure source code quality, from the portfolio to the method."
    website "https://www.sonarqube.org"
    
    # This is the matches array. 
    # Each match is treated independently.
    
    # Matches #
    matches [
    
    # This searches for a text string.
    { :text => '<title>SonarQube</title>' },
    
    # This searches for a regular expression. Note that the slashes are escaped.
    { :regexp =>/sonar.css\?v=/ },
    
    { :version => /sonar.css\?v=(.*?)"/ }, 
    
    ] 
    
    end