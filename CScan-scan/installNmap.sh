git clone https://github.com/nmap/nmap
mv ./nmap ./nmapsource
cd ./nmapsource && ./configure
make && make install
cd .. && rm -rf ./nmapsource
mkdir nmap && cp `which nmap` ./nmap/nmap