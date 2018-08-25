Plugin.define "Grafana" do
    author "orange <clinlee.me@gmail.com>"
    description "Grafana.net makes it easy for anyone to visualize, share, scale and protect their time series data, no matter where it lives. Take back control of your monitoring, and avoid the vendor lock in and spiraling costs of closed solutions."
    website "http://grafana.org"
    
    # This is the matches array. 
    # Each match is treated independently.
    
    # Matches #
    matches [
    
    # This searches for a text string.
    { :text => '<title>Grafana</title>' },
    
    # This searches for a regular expression. Note that the slashes are escaped.
    { :regexp => /grafana-app/ },
    
    { :version => /"version":"(.*?)"},"datasources":/ }, 
    
    ] 
    
    end