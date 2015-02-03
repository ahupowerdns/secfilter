#include <iostream>
#include <fstream>
#include <sys/ptrace.h>
#include <boost/algorithm/string.hpp>
#include <fcntl.h>
#include <boost/program_options.hpp>
#include "iputils.hh"
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include "gather.hh"

namespace po = boost::program_options;
po::variables_map g_vm;
                     
using namespace std;
extern "C" 
{
#include "seccomp-bpf.h"
}
#include <sys/user.h>  
#include <sys/types.h>
#include <sys/wait.h>

NetmaskGroup g_nmg;
std::unordered_set<unsigned int> g_allowedPorts;
std::unordered_set<string> g_allowWrite;
bool g_verbose;

void processConfig(int argc, char** argv)
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("config,c", po::value<string>(), "configuration file")
    ("allow-write", po::value<vector<string> >(), "only write here")
    ("allow-resolv", "Specifically allow resolution of domain names")
    ("mainstream-network-families", "only allow AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK")
    ("no-outbound-network", po::value<bool>()->default_value(false), "no outgoing network connections")
    ("allowed-netmask", po::value<vector<string> >(), "only allow access to these masks")
    ("allowed-port", po::value<vector<int> >(), "allow access to this port")
    ("verbose,v", "be verbose and write a log file to ./log")
    ("read-only", po::value<bool>()->default_value(false), "be read-only");

  try {
    int i=1;
    for(i=1; i < argc; ++i)
      if(*argv[i] != '-')
	break;

    po::store(po::command_line_parser(i, argv).options(desc).run(), g_vm);
    po::notify(g_vm);

    if(g_vm.count("config")) {
      std::ifstream settings_file( g_vm["config"].as<string>() , std::ifstream::in );
      po::store(po::parse_config_file(settings_file, desc), g_vm);
      po::store(po::command_line_parser(i, argv).options(desc).run(), g_vm);
      po::notify(g_vm);
    }


    if(g_vm.count("allow-write"))
    for(const auto& a : g_vm["allow-write"].as<vector<string> >()) {
      g_allowWrite.insert(a);
    }

    g_verbose=g_vm.count("verbose");
    
    if(g_vm.count("allowed-netmask"))
    for(const auto& a : g_vm["allowed-netmask"].as<vector<string> >()) {
      g_nmg.addMask(a);
    }

    if(g_vm.count("allowed-port"))
    for(const auto& a : g_vm["allowed-port"].as<vector<int> >()) {
      g_allowedPorts.insert(a);
    }


    if(g_vm.count("help")) {
      cout<<desc<<endl;
      exit(EXIT_SUCCESS);
    }

    if(g_vm.count("allow-resolv")) {
      if(!g_allowedPorts.empty())
	g_allowedPorts.insert(53);
      auto resolvers = parseResolveConf();
      if(!g_nmg.empty()) {
	for(const auto& a: resolvers)
	  g_nmg.addMask(a.toString());
      }
    }
  }
  catch(std::exception& e) {
    cerr<<"Error parsing options: "<<e.what()<<endl;
    cout<<desc<<endl;
    exit(EXIT_SUCCESS);
  }
}

struct HandlerSet
{
  HandlerSet(pid_t child, user_regs_struct& regs, ofstream& logger) 
    : d_child(child), d_regs(regs), d_logger(logger) {}

  void openHandler();
  void testHandler(int) {}
  void openatHandler();
  void connectHandler();
  void sendtoHandler();
  void sendmsgHandler();
  void unlinkHandler();
  void unlinkatHandler();
  void chdirHandler();
  void socketHandler();

  pid_t d_child;
  user_regs_struct& d_regs;
  ofstream& d_logger;
};

unordered_map<unsigned int, function<void(HandlerSet&)>> g_handlers;

#define TRACE_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#define TRACE_SYSCALLNO(no) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, no, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)


static int install_syscall_filter(void)
{
	vector<sock_filter> filter;
	for(const sock_filter& a : initializer_list<sock_filter>{VALIDATE_ARCHITECTURE})
	  filter.push_back(a);
	filter.push_back(EXAMINE_SYSCALL);
	for(const auto& a : g_handlers) 
	  for(const auto& b : initializer_list<sock_filter>{TRACE_SYSCALLNO(a.first)})
	    filter.push_back(b);
	filter.push_back(BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW));

	struct sock_fprog prog = {
	  .len = (unsigned short)filter.size(),
	  .filter = &filter[0],
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL)
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	return 1;
}

string getcwdFor(pid_t pid)
{
  string path="/proc/"+to_string(pid)+"/cwd";
  char buffer[256];
  if(readlink(path.c_str(), buffer, sizeof(buffer)) < 0) {
    perror("readlink");
    exit(1);
  }
  return buffer;
}

string getcwdForDir(pid_t pid, int fd)
{
  if(fd == AT_FDCWD)
    return ".";

  string path="/proc/"+to_string(pid)+"/fd/"+to_string(fd);
  char buffer[256];
  if(readlink(path.c_str(), buffer, sizeof(buffer)) < 0) {
    perror(("readlink for "+path).c_str());
    exit(1);
  }
  return buffer;
}

string Realpath(const string& path)
{
  char *p = realpath(path.c_str(), 0);
  if(!p) {
    if(errno == ENOENT)
      return path;
    perror("realpath");
    exit(1);
  }
  string ret(p);
  free(p);
  return ret;
}


void cleanupPath(string& path)
{
  boost::replace_all(path, "//", "/");
  boost::replace_all(path, "/./", "/");
  path=Realpath(path);
}


string getPtraceString(pid_t child, long long unsigned int address)
{
  string ret;
  for (int i = 0; i < 255; i++) {
    unsigned int c = ptrace(PTRACE_PEEKTEXT, child, address + i, 0);
    if ((c & 0xff) == 0) break;
    ret.append(1, c & 0xff);
  }	
  return ret;
}

void justSayNo(pid_t child, user_regs_struct& regs, int error=EPERM)
{
  regs.orig_rax=-error;
  regs.rax=-1;
  if(ptrace(PTRACE_SETREGS, child, NULL, &regs)) {
    perror("setregs");
    exit(1);
  }          
}

void hookChild(pid_t child)
{
  if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACESECCOMP |PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK )) {
    perror("strace setoptions exec");
    exit(1);
  }
}

string getFullPath(pid_t child, unsigned long long fileptr)
{
  string path=getPtraceString(child, fileptr);

  if(!path.empty() && path[0]!='/')
    path=getcwdFor(child)+"/"+path;

  cleanupPath(path);

  return path;
}

unsigned long long getArg1(const struct user_regs_struct& regs)
{
  return regs.rdi;
}

unsigned long long getArg2(const struct user_regs_struct& regs)
{
  return regs.rsi;
}

unsigned long long getArg3(const struct user_regs_struct& regs)
{
  return regs.rdx;
}

unsigned long long getArg4(const struct user_regs_struct& regs)
{
  return regs.rcx;
}

unsigned long long getArg5(const struct user_regs_struct& regs)
{
  return regs.r8;
}

unsigned long long getArg6(const struct user_regs_struct& regs)
{
  return regs.r9;
}

string getFullPathAt(pid_t child, unsigned long long fd, unsigned long long fileptr)
{
  string relpath=getPtraceString(child, fileptr);

  string path;
  if(!relpath.empty() && relpath[0]!='/') 
    path=getcwdForDir(child, fd)+"/"+relpath;
  else path=relpath;

  cleanupPath(path);
  return path;
}

void getPtraceBytes(pid_t child, char* dest, unsigned long long src, unsigned long long bytes)
{
 for(auto i = 0*bytes; i < bytes; ++i) {
    unsigned int c = ptrace(PTRACE_PEEKTEXT, child, src + i, 0);
    memcpy(dest+i, &c, 1);
  }
 
}

ComboAddress getPtraceComboAddress(pid_t child, unsigned long long sockaddr, unsigned long long socklen)
{
  ComboAddress ret;

  for(unsigned int i = 0; i < socklen && i < sizeof(ret); ++i) {
    unsigned int c = ptrace(PTRACE_PEEKTEXT, child, sockaddr + i, 0);
    memcpy(((char*)&ret)+i, &c, 1);
  }
  return ret;
}

bool checkNetworkPolicy(const std::string& what, const ComboAddress& dest, pid_t child, ofstream& logger)
{
  if(g_vm["no-outbound-network"].as<bool>())
    return false;

  if(dest.sin4.sin_family == AF_INET || dest.sin4.sin_family == AF_INET6) {
    if(g_verbose)
      logger<<child<<": Wants to "<<what<<" to "<<dest.toStringWithPort()<<endl;
    if(!g_nmg.empty() && !g_nmg.match(dest)) {
      logger<<child<<": denied connection to to "<<dest.toStringWithPort()<<endl;
      return false;
    }
    if(!g_allowedPorts.empty() && !g_allowedPorts.count(htons(dest.sin4.sin_port))) {
      logger<<child<<": denied connection to to "<<dest.toStringWithPort()<<" based on port"<<endl;
      return false;
    }
  }
  return true;

}

bool checkWritePolicy(const string& path, pid_t child, ofstream& logger)
{
  if(!g_allowWrite.empty()) {
    for(const auto& w : g_allowWrite) {
      if(boost::starts_with(path, w)) {
	return true;
      }
    }
    logger<<child<<": open of '"<<path<<"' denied, did not start with any of "<<endl;
    for(const auto& w : g_allowWrite) {
      logger<<child<<":     "<<w<<endl;
    }
    return false;
  }

  if(g_vm["read-only"].as<bool>()) 
    return false;

  return true;
}

void HandlerSet::openHandler()
{
  string path = getFullPath(d_child, d_regs.rdi);
  int mode=d_regs.rsi & 0xffff;
  if(g_verbose)
    d_logger<<d_child<<": Wants to open absolute path: '"<<path<<"', mode "<<mode<< ", "<<(mode & O_WRONLY)<<", "<<(mode & O_RDWR)<<endl;
  
  if((mode & O_WRONLY) || (mode & O_RDWR)) {
    if(!checkWritePolicy(path, d_child, d_logger)) {
      d_logger<<d_child<<": open denied"<<endl;
      justSayNo(d_child, d_regs);
    }
  }  
}

void HandlerSet::openatHandler()
{

  string path=getFullPathAt(d_child, d_regs.rdi, d_regs.rsi);
  int mode=d_regs.rdx & 0xffff;

  if(g_verbose)
    d_logger<<d_child<<": Wants to openat absolute path: '"<<path<<"', mode "<<mode<< ", "<<(mode & O_WRONLY)<<", "<<(mode & O_RDWR)<<endl;
  if((mode & O_WRONLY) || (mode & O_RDWR)) {
    if(!checkWritePolicy(path, d_child, d_logger)) {
      d_logger<<d_child<<": openat denied "<<(mode&O_WRONLY) <<", "<<(mode & O_RDWR)<<endl;
      justSayNo(d_child, d_regs);
    }
  }
}

void HandlerSet::connectHandler()
{
// rdi, rsi, rdx = socket, addressptr, length
  
  ComboAddress dest=getPtraceComboAddress(d_child, d_regs.rsi, d_regs.rdx);
  if(!checkNetworkPolicy("connect", dest, d_child, d_logger)) {
    justSayNo(d_child, d_regs);
  }
}

void HandlerSet::sendtoHandler()
{
  // ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
  //                const struct sockaddr *dest_addr, socklen_t addrlen);
  
  if(!getArg5(d_regs))  // this means 'send()'
    return;
  ComboAddress dest=getPtraceComboAddress(d_child, getArg5(d_regs), getArg6(d_regs));
  if(!checkNetworkPolicy("sendto", dest, d_child, d_logger)) {
    justSayNo(d_child, d_regs);
  }
}


void HandlerSet::sendmsgHandler()
{
  // ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);

  struct msghdr msg;
  getPtraceBytes(d_child, (char*)&msg, getArg2(d_regs), sizeof(msg));
  ComboAddress dest=getPtraceComboAddress(d_child, (unsigned long long)msg.msg_name, msg.msg_namelen);

  if(!checkNetworkPolicy("sendmsg", dest, d_child, d_logger)) {
    justSayNo(d_child, d_regs);
  }
}

void HandlerSet::unlinkHandler()
{
  string path = getFullPath(d_child, d_regs.rdi);
  if(g_verbose)
    d_logger<<d_child<<": wants to unlink '"<<path<<"'"<<endl;
  if(!checkWritePolicy(path, d_child, d_logger)) {
    d_logger<<d_child<<": unlink denied"<<endl;
    justSayNo(d_child, d_regs);
  }
}

void HandlerSet::unlinkatHandler()
{
  string path = getFullPathAt(d_child, d_regs.rdi, d_regs.rsi);
  if(g_verbose)
    d_logger<<d_child<<": wants to ulinkat '"<<path<<"'"<<endl;
  if(!checkWritePolicy(path, d_child, d_logger)) {
    d_logger<<d_child<<": unlinkat denied"<<endl;
    justSayNo(d_child, d_regs);
  }
}

void HandlerSet::chdirHandler()
{
  // we just hook this so we can prevent other threads from being crafty under us
}

void HandlerSet::socketHandler() 
{
  if(!g_vm.count("mainstream-network-families"))
    return;
  
  for(decltype(d_regs.rdi) i : {AF_INET, AF_INET6, AF_UNIX, AF_NETLINK})
    if(d_regs.rdi == i)
      return;
  
  d_logger<<d_child<<": denying creation of socket of type "<<d_regs.rdi<<endl;
  justSayNo(d_child, d_regs);
}

int main(int argc, char** argv)
try
{
  processConfig(argc, argv);
  
  pid_t child=fork();

  g_handlers.insert({
      {__NR_open,       &HandlerSet::openHandler},
	{__NR_openat,   &HandlerSet::openatHandler},
	{__NR_connect,  &HandlerSet::connectHandler},
	{__NR_sendto,   &HandlerSet::sendtoHandler},
	{__NR_chdir,    &HandlerSet::chdirHandler},
	{__NR_fchdir,   &HandlerSet::chdirHandler},
	{__NR_sendmsg,  &HandlerSet::sendmsgHandler},
	{__NR_unlink,   &HandlerSet::unlinkHandler},
	{__NR_unlinkat, &HandlerSet::unlinkatHandler},
	{__NR_socket,   &HandlerSet::socketHandler}
      });
  
  if(child) {
    signal(SIGINT, SIG_IGN);

    ofstream logger("log");
    logger<<"Our child is "<<child<<endl;
    int status;
    struct user_regs_struct regs; 
    int numchildren=1;
    while(numchildren && (child=waitpid(-1, &status,__WALL ))) {
      //      logger<<child<<": status: "<<status<<endl;
      if(WIFEXITED(status)) {
	logger<<child<<": exited"<<endl;
	--numchildren;
	continue;
      }
      hookChild(child);

      if(status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
	pid_t newchild;
	if(ptrace(PTRACE_GETEVENTMSG, child, 0, &newchild) < 0) {
	  perror("geteventmsg");
	  exit(1);
	}
	logger<<child<<": Got new child to trace "<<newchild<<endl;
	numchildren++;

      }
      if(status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
	pid_t newchild;
	if(ptrace(PTRACE_GETEVENTMSG, child, 0, &newchild) < 0) {
	  perror("geteventmsg");
	  exit(1);
	}
	logger<<child<<": Got new child to trace "<<newchild<<endl;
	numchildren++;
      }
      if(status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
	pid_t newchild;
	if(ptrace(PTRACE_GETEVENTMSG, child, 0, &newchild) < 0) {
	  perror("geteventmsg");
	  exit(1);
	}
	logger<<child<<": Got new THREAD to trace "<<newchild<<endl;
	//	hookChild(newchild);
	ptrace(PTRACE_CONT, newchild, NULL, NULL);         // go on then

	numchildren++;
      }
      if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs)) {
	  perror("getregs");
	  exit(1);
	}
	
	logger<<child<<": Got an exec, unsure what to do with it.."<<endl;
	//	logger<<child<<": got exec for '"<<getPtraceString(child, regs.rdi)<<"'"<<endl;
	hookChild(child);
      }

      if(WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
	logger<<child<<": Got signal "<<WSTOPSIG(status)<<endl;
	if(WSTOPSIG(status) != SIGSTOP)
	  ptrace(PTRACE_CONT, child, NULL, WSTOPSIG(status));        
	else
	  ptrace(PTRACE_CONT, child, NULL, 0);        
	continue;
      }

      if(ptrace(PTRACE_GETREGS, child, NULL, &regs)) {
        perror("getregs");
        exit(1);
      }

      auto handler = g_handlers.find(regs.orig_rax);
      if(handler != g_handlers.end()) {
	HandlerSet hs(child, regs, logger);
	handler->second(hs);
      }
      else if (regs.orig_rax == __NR_execve || regs.orig_rax == __NR_vfork || regs.orig_rax==__NR_fork || regs.orig_rax==__NR_clone) {
	// we get these, but no need to do anything
      }
      else 
	logger<<child<<": untracked system call "<<regs.orig_rax<<endl;
      ptrace(PTRACE_CONT, child, NULL, NULL);        
    }
  }
  else {
    if(ptrace(PTRACE_TRACEME, 0,0,0)) {
      perror("ptrace");
      exit(1);
    }
    char* chargs[argc];
    int i, pos=0;

    for(i=1 ; i < argc ; ++i) {
      if(*argv[i]!='-')
	break;
    }
    
    while (i < argc) {
      chargs[pos++] = argv[i];
      i++;
    }
    chargs[pos] = NULL;
    
    if (install_syscall_filter())
      return 1;
      
    if(execvp(chargs[0], chargs)) {
      perror("execvp");
      exit(1);
    }
  }
}
catch(exception& e) {
  cerr<<"Got killed by an exception: "<<e.what()<<endl;
}
