(D)TLS Handshake using mbedtls.
===================

Clone
-----
The project includes submodules. Remember to clone those as well.
git clone --recurse-submodules <repository-url>
or if you already cloned the repository
git submodule update --init --recursive

Compiling
---------
cmake --preset dtls-handshake-debug
cmake --build build

Running and Analyzing
---------------------
./build/my_app > dump.txt
text2pcap.exe -u 443,443 .\dump.txt dump.pcap

dump.pcap can then be opened in Wireshark.
In Wireshark:
* Edit -> Preferences -> Protocol -> TLS -> "(Pre)-Master-Secret log filename"
* Browse to nss_keylog_file, which is created by running the my_app executable.
