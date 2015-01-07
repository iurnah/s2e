g++ -std=c++0x parser.cpp -o parser1

../parser -a memory.txt > type_addr.txt
../parser -m1 memory.txt > sec_count1.txt
../parser -m2 memory.txt > addr_count2.txt
../parser -m3 memory.txt > path_count3.txt

g++ -std=c++11 -Wall -O3 -finline-functions -lboost_regex -o boost_test boost_test.cpp
