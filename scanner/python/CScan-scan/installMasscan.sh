apt-get install git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
mv ./masscan ./masscansource
cd ./masscansource && make
cd .. && mkdir masscan && cp ./masscansource/bin/masscan ./masscan/masscan
rm -rf ./masscansource