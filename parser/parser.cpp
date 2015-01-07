/* parsing the memory.txt file analysis results
 */
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <regex>
#include <assert.h>

//using namespace std;

std::regex reg1("s:(\\d+)m:(\\d+)u:(\\d+)n:(\\d+).*State\\s(\\d+)]");   //time and state
//std::regex reg1("s:(\\d*)m:(\\d{3})u:(\\d{6})n:(\\d{9}).*State\\s(\\d+)]");   //time and state
std::regex reg2("(\\w*|\\w*\\b\\s\\w*|\\w*\\b __user \\*) __user \\*\\[(.*?)\\]");//data type and value
std::regex reg3("Statistics=(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+)"); //the eight statistics

typedef class Entry{
public:
	Entry();
	Entry(std::string ent);
	~Entry();

	long sec;
	long millisecond;
	long microsecond;
	long nanosecond;

	int stateId;//pathId;
	std::map <std::string, std::string> parameters;

	int syscallTotal;
	int pointerTotal;
	int OWPointerTotal; 
	int resultpointerTotal;

	int syscallState;
	int pointerState;
	int OWPointerState;
	int resultpointerState;
}EntryObj;

Entry::Entry(std::string ent){
	std::smatch m;
	std::string::size_type sz;
	std::string ent1(ent);
	std::string ent2(ent);
	std::string ent3(ent);
	//construct the time + state values
	while (std::regex_search(ent1, m, reg1)) {
		for(int i = 1; i < m.size(); i++){
			//std::cout << m[i] << '\n' ;
		}
		sec = std::stol (m[1], nullptr, 0);
		millisecond = std::stol (m[2], nullptr, 0);
		microsecond = std::stol (m[3], nullptr, 0);
		nanosecond = std::stol (m[4], nullptr, 0);
		stateId = std::stol (m[5], nullptr, 0);

		ent1 = m.suffix().str();
	}
	//construct the address and data type 
	while(std::regex_search(ent2, m, reg2)){
		for(int i = 1; i < m.size(); i++){
			//std::cout << m[i] << m.size() << std::endl;
		}

		if((m[2] != "0xdeadbeef") && (m[2] != "0x0") && (m[2].length() > 6)){
			parameters.insert(std::pair<std::string, std::string>(m[1], m[2]));
//			std::cout << m[1] << " + " << m[2] << std::endl;
		}
		ent2 = m.suffix().str();
	}
	//construct the statistics
	while(std::regex_search(ent3, m, reg3)){
		for(int i = 1; i < m.size(); i++){
			//std::cout << m[i] << std::endl;
		}

		syscallTotal = stoi(m[1], nullptr, 0);
		pointerTotal= stoi(m[2], nullptr, 0);
		OWPointerTotal = stoi(m[3], nullptr, 0); 
		resultpointerTotal = stoi(m[4], nullptr, 0);

		syscallState = stoi(m[5], nullptr, 0);
		pointerState = stoi(m[6], nullptr, 0);
		OWPointerState = stoi(m[7], nullptr, 0);
		resultpointerState = stoi(m[8], nullptr, 0);

		ent3 = m.suffix().str();
	}
	//std::cout << "finished Constructor" << std::endl;
}

static void show_usage(std::string name)
{
	std::cerr << "Usage: " << name << " <option> \n"
			  << "Options:\n"
			  << "\t-a --show-address\tprint the reversed addresses and its types.\n"
			  << "\t-m1 --metric1\t print the metric1 data file.\n "
			  << "\t-m2 --metric2\t print the metric2 data file.\n "
			  << "\t-m3 --metric3\t print the metric3 data file.\n "
			  << std::endl;

}

void print_allAddresses(std::vector<EntryObj *>& EntryObj_vec){
	//std::cout << "time(sec:microsec) dataType memoryValue" << std::endl;
	std::cout << "memoryValue\tdataType" << std::endl;
	std::vector<EntryObj *>::iterator it;
	std::cout << "Begin_t=" << (*EntryObj_vec.begin())->sec << std::endl;
	for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
		if(!(*it)->parameters.empty()){
			 

			std::map<std::string, std::string>::iterator it_map;
			for (it_map = (*it)->parameters.begin(); it_map != (*it)->parameters.end(); it_map++){
				//std::cout << (*it)->sec << "." << (*it)->microsecond << " ";
				std::cout << it_map->second << "\t" << "(" << it_map->first<< ")" << std::endl;
			}
		}
	}

	return;
}

void metric1(std::vector<EntryObj *>& EntryObj_vec){
	assert(!EntryObj_vec.empty());

	std::vector<int> counts;
	long begin_t = (EntryObj_vec.front())->sec;
	int cnt = 0;
    int	prev_t = 0;

	std::cout << "time\tcounts" << std::endl;
	std::vector<EntryObj *>::iterator it;
	for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
		int t = (*it)->sec - begin_t;

		if(prev_t != t){//sec change, we push_back, and set cnt=0;
			counts.push_back(cnt);
			cnt = 0;	
			prev_t = t;
		}

		if(!(*it)->parameters.empty()){
			cnt += (*it)->parameters.size();
		}
	}

	counts.push_back(cnt);//last group because we cannot detect sec change.

	for(int i = 0; i < counts.size(); i++){
		std::cout << i+1 << "\t" << counts[i] << std::endl;
	}

	return;
}

/* How many path discovered this address? */
void metric2(std::vector<EntryObj *> EntryObj_vec){
	assert(!EntryObj_vec.empty());
	std::map<std::string, std::vector<int>> addresses;

	std::vector<EntryObj *>::iterator it;
	for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
		if(!(*it)->parameters.empty()){

			std::map<std::string, std::string>::iterator it_map;
			for(it_map = (*it)->parameters.begin(); it_map != (*it)->parameters.end(); it_map++){
				if(addresses.find(it_map->second) == addresses.end()){
					//the address is not in the map, add new entry to the addresses.
					std::vector<int> pathIds;
					pathIds.push_back((*it)->stateId);
					addresses.insert(std::pair<std::string, std::vector<int>>(it_map->second, pathIds));
				}else{
					//the address is in the map, check the id, if different, add to the vec
					if(std::find(addresses[it_map->second].begin(), addresses[it_map->second].end(), (*it)->stateId) != addresses[it_map->second].end()){	
					//if(addresses[it_map->second].find(stateId) == addresses[it_map->second].end()){
						addresses[it_map->second].push_back((*it)->stateId);
					}else{
						//TODO:same stateId discovered this address.
					}
				}
			}
		}
	}

	std::cout << "address" << "\t" << "times(discovered)" << std::endl;
	std::map<std::string, std::vector<int>>::iterator addr_map;
	for(addr_map = addresses.begin(); addr_map != addresses.end(); ++addr_map){
		std::cout << addr_map->first << "\t" << addr_map->second.size() << std::endl;
	}

	return;
}

/* Useful datastructure distributed across paths(x: pathId, y: # of useful
 * datastructure */
void metric3(std::vector<EntryObj *> EntryObj_vec){
	assert(!EntryObj_vec.empty());

	std::map<int, std::vector<std::string>> PathIdMap;
	std::vector<std::string> addrs;
	std::vector<EntryObj *>::iterator it;
	for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
		if(!(*it)->parameters.empty()){
			std::map<std::string, std::string>::iterator it_map;
			for(it_map = (*it)->parameters.begin(); it_map != (*it)->parameters.end(); it_map++){
				addrs.push_back(it_map->second);	
			}
			PathIdMap.insert(std::pair<int, std::vector<std::string>>((*it)->stateId, addrs));
		}
	}

	//print to the std output the results.
	std::cout << "stateId" << "\t" << "addresses" << std::endl;
	std::map<int, std::vector<std::string>>::iterator path_addr;
	for(path_addr = PathIdMap.begin(); path_addr != PathIdMap.end(); ++path_addr){
		std::cout << path_addr->first << "\t" << path_addr->second.size() << "\t";
		std::vector<std::string>::iterator it_vec;
		for(it_vec = path_addr->second.begin(); it_vec != path_addr->second.end(); ++it_vec){
			//std::cout << *it_vec << "\t";	
		}
		std::cout << std::endl;
	}
	return;
}

int main(int argc, char**argv){
	std::ifstream memorytxt;
	memorytxt.open("memory.txt");
	int count;
	std::vector<EntryObj *> EntryObj_vec;
	EntryObj *EntryObjPtr;
	std::string lineEntry;

	if(argc < 2){
		show_usage(argv[0]);
		return 1;
	}

	while(std::getline(memorytxt, lineEntry))
	{
		EntryObjPtr = new EntryObj(lineEntry);
		
		EntryObj_vec.push_back(EntryObjPtr);
	}

	std::string arg = argv[1];
	if((arg == "-h") || (arg == "--help")){
		show_usage(argv[0]);
		return 0;
	}else if((arg == "-a") || (arg == "--show-address")){
		print_allAddresses(EntryObj_vec);
	}else if((arg == "-m1") || (arg == "--metric1")){
		metric1(EntryObj_vec);
	}else if((arg == "-m2") || (arg == "--metric2")){
		metric2(EntryObj_vec);
	}else if((arg == "-m3") || (arg == "--metric3")){
		metric3(EntryObj_vec);
	}else if((arg == "-m4") || (arg == "--metric4")){
		std::cout << "Please specify the correct options" << std::endl;	
	}
#if 0
	std::vector<EntryObj *>::iterator it;
	for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
		std::cout << "stateId=" << (*it)->stateId << std::endl;
		std::cout << "sec=" << (*it)->sec << std::endl;
		std::cout << "msec=" << (*it)->millisecond << std::endl;
		std::cout << "usec=" << (*it)->microsecond << std::endl;
		std::cout << "nsec=" << (*it)->nanosecond << std::endl;

		std::map<std::string, std::string>::iterator it_map;
		for (it_map = (*it)->parameters.begin(); it_map != (*it)->parameters.end(); it_map++){
			std::cout << it_map->first << " + " << it_map->second << std::endl;
		}

		std::cout << "total=" << (*it)->syscallTotal << std::endl;
		std::cout << "ptr=" << (*it)->pointerTotal << std::endl;
		std::cout << "OWptr=" << (*it)->OWPointerTotal << std::endl;
		std::cout << "useful_ptr=" << (*it)->resultpointerTotal << std::endl;

		std::cout << "statetotal=" << (*it)->syscallState << std::endl;
		std::cout << "stateptr=" << (*it)->pointerState << std::endl;
		std::cout << "stateOWptr=" << (*it)->OWPointerState << std::endl;
		std::cout << "state_ptr=" << (*it)->resultpointerState << std::endl;
	}
#endif
	std::cout << "Total size = " << EntryObj_vec.size() << std::endl;
	return 0;
}
