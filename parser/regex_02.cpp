// regex_search example
#include <iostream>
#include <string>
#include <regex>

int main ()
{
  //std::string s ("this subject has a submarine as a subsequence");
  //std::string s ("s:470091567m:254u:254309n:254309000 145 [State 44]");
  //std::string s ("s:470091568m:374u:374125n:374126000 146 [State 2] sys_futex (u32 __user *[0xdeadbeef],  int[0x81],  u32[0x1],  struct timespec __user *[0xdeadbeef],  u32 __user *[0x80a8278],  u32[0xdeadbeef]); Statistics=384, 138, 103, 35, 35, 15, 10, 5");
	std::string s ("s:470091567m:280u:280903n:280903000 145 [State 0] sys_execve (char __user *[0xdeadbeef],  char __user * __user *[0xdeadbeef],  char __user * __user *[0x823a008]); Statistics=199, 69, 60, 9, 199, 69, 60, 9");
  std::smatch m;
  
  std::regex e ("s:(\\d*)m:(\\d*)u:(\\d{6})n:(\\d{9}).*State\\s(\\d+)].*;");   //time and state
  //std::regex e ("(\\w*|\\w*\\b\\s\\w*|\\w*\\b __user \\*) __user \\*\\[(.*?)\\]");//data type and value
  //std::regex e ("Statistics=(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+),\\s(\\d+)"); //the eight statistics

  std::cout << "Target sequence: " << s << std::endl;
  std::cout << "Regular expression: " << std::endl;
  std::cout << "The following matches and submatches were found:" << std::endl;

  while (std::regex_search(s, m, e)) {
	for(int i = 1; i < m.size(); i++)
		std::cout << m[i] << '\n' ;
    std::cout << std::endl;
    s = m.suffix().str();
  }
	std::cout << m.suffix() << std::endl;
  return 0;
}
