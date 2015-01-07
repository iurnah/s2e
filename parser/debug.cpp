#include <iostream>
#include <vector>
#include <map>

struct EntryObj { int sec; int microsecond; std::map<std::string, std::string> parameters; };

void print_allAddresses(std::vector<EntryObj *> EntryObj_vec){
    std::cout << "time(sec:microsec) dataType memoryValue" << std::endl;
    std::vector<EntryObj *>::iterator it;
    it = EntryObj_vec.begin();
    std::cout << "sec " << (*it)->sec << std::endl; //EntryObj_vec.front()->sec also wrong here.
    for(it = EntryObj_vec.begin(); it != EntryObj_vec.end(); ++it){
        if(!(*it)->parameters.empty()){
            std::cout << (*it)->sec << "." << (*it)->microsecond << " "; 

            std::map<std::string, std::string>::iterator it_map;
            for (it_map = (*it)->parameters.begin(); it_map != (*it)->parameters.end(); it_map++){
                std::cout << "(" << it_map->first<< ")" << " " << it_map->second << std::endl;
            }
        }
    }
    return;
}

int main()
{
	std::vector<EntryObj*> v {
		new EntryObj { 11, 111, { { "A1", "Aone" }, { "A2", "Atwo" } } },
		new EntryObj { 22, 222, { { "B1", "Bone" }, { "B2", "Btwo" } } }
	};
	print_allAddresses(v);
}