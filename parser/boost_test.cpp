#include <iostream>
#include <string>
#include <boost/regex.hpp>
 
using namespace std;
using namespace boost;
 
bool checkEmail(const string& email){
    regex reg("\\w+([-+.]\\w+)*@\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*");
 
    return regex_match(email.c_str(),reg);
}
 
string getHost(const string& url){
    regex reg("https?://([^/]+).*");
    cmatch what;
 
    if (regex_match(url.c_str(),what,reg)){
        return what[1];
    }
     
    return "";
}
 
string getATag(const string& str){
    regex reg("<a.*?title='([^']+)'[^>]+>\\1</a>");
    cmatch what;
 
    if (regex_match(str.c_str(),what,reg)){
        return what[1];
    }
     
    return "";
}
 
string searchUsername(const string& str){
    regex reg("username=([^&]+)");
    string::const_iterator start(str.begin()),
                            end(str.end());
    match_results<string::const_iterator> what;
 
    if (regex_search(start,end,what,reg,match_default)){
        return what[1];
    }
 
    return "";
}
 
string searchAllArgs(const string& str){
    regex reg("([^&]+)=([^&]+)");
    string::const_iterator start(str.begin()),
                            end(str.end());
    match_results<string::const_iterator> what;
    string res("");
 
    while (regex_search(start,end,what,reg,match_default)){
        res+=what[1] + " => " + what[2] + '\n';
        start=what[0].second;
    }
 
    return res;
}
 
string replaceHello(const string& str){
    regex reg("(?<![a-zA-Z])hello(?![a-zA-Z])");
    string target("olleh");
 
    string res=regex_replace(str,reg,target);
 
    return res;
}
 
string replaceTo3(const string& str){
    regex reg("([a-zA-Z]+)2");
    string target("\\13");
 
    string res=regex_replace(str,reg,target);
     
    return res;
}
 
int main(int argc,char *argv[]){
     
    string email("root@sbwtw.org");
    if (checkEmail(email)){
        cout<<"it's a email address"<<endl;
    } else {
        cout<<"it's NOT a email address"<<endl;
    }
 
    string url("http://blog.shibowen.com/art-50.html");
    cout<<getHost(url)<<endl;
 
    string aTag("<a title='sbw' href='/index.php'>sbw</a>");
    cout<<getATag(aTag)<<endl;
 
    string uri1("id=50&username=sbw&password=root");
    cout<<searchUsername(uri1)<<endl;
 
    string uri2("a=1111&bb=222&ccc=33&dddd=4");
    cout<<searchAllArgs(uri2);
 
    string content1("hello, world! hello2, world. hello hell helloabc hello");
    cout<<content1<<endl
        <<replaceHello(content1)<<endl;
 
    string content2("sbw sbw2 abc abc2 cde4 cde cde2");
    cout<<content2<<endl
        <<replaceTo3(content2)<<endl;
 
    return 0;
}
