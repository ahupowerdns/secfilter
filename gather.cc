#include "gather.hh"
#include <fstream>
#include <boost/algorithm/string.hpp>

using namespace std;

vector<ComboAddress> parseResolveConf()
{
  vector<ComboAddress> ret;
  ifstream ifs("/etc/resolv.conf");
  if(!ifs)
    return ret;

  string line;
  while(std::getline(ifs, line)) {
    boost::trim_right_if(line, boost::algorithm::is_any_of(" \r\n\x1a"));
    boost::trim_left(line); // leading spaces, let's be nice

    string::size_type tpos = line.find_first_of(";#");
    if(tpos != string::npos)
      line.resize(tpos);

    if(boost::starts_with(line, "nameserver ") || boost::starts_with(line, "nameserver\t")) {
      vector<string> parts;
      stringtok(parts, line, " \t,"); // be REALLY nice
      for(vector<string>::const_iterator iter = parts.begin()+1; iter != parts.end(); ++iter) {
        
        try {
          ret.push_back(ComboAddress(*iter, 53));
        }
        catch(...)
        {
        }
      }
    }

  }
  if(ret.empty()) {
    ret.push_back(ComboAddress("127.0.0.1", 53));
  }

  return ret;
}
