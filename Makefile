all : arp_spoof

arp_spoof: 
	g++ -std=c++11 arp_spoof.cpp -o arp_spoof -lpcap -pthread

clean:
	rm -f arp_spoof
