#include <iostream>
#include <fstream>
#include <sys/ptrace.h>
#include <boost/algorithm/string.hpp>
#include <fcntl.h>
#include <boost/program_options.hpp>
#include "iputils.hh"

namespace po = boost::program_options;
po::variables_map g_vm;
                     
using namespace std;
extern "C" 
{
#include "seccomp-bpf.h"
#include <sys/user.h>  
}

#include <sys/types.h>
#include <sys/wait.h>

NetmaskGroup g_nmg;

void processConfig(int argc, char** argv)
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("write-allow", po::value<string>(), "only write here")
    ("no-outbound-network", po::value<bool>()->default_value(false), "no outgoing network connections")
    ("allowed-netmasks", po::value<string>()->default_value("0.0.0.0/0"), "only allow access to these maskas")
    ("allowed-ports", po::value<int>(), "only allow access to these ports")
    ("read-only", po::value<bool>()->default_value(false), "be read-only");

  try {
    int i=1;
    for(i=1; i < argc; ++i)
      if(*argv[i] != '-')
	break;

    po::store(po::command_line_parser(i, argv).options(desc).run(), g_vm);
    po::notify(g_vm);

    
    g_nmg.addMask(g_vm["allowed-netmasks"].as<string>());

    if(g_vm.count("help")) {
      cout<<desc<<endl;
      exit(EXIT_SUCCESS);
    }


    /*
    std::ifstream settings_file( config , std::ifstream::in );
    po::store(po::parse_config_file(settings_file, desc), g_vm);
    po::notify(g_vm);
    */
  }
  catch(std::exception& e) {
    cerr<<"Error parsing options: "<<e.what()<<endl;
    cout<<desc<<endl;
    exit(EXIT_SUCCESS);
  }
}


#define TRACE_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

static int install_syscall_filter(void)
{
	struct sock_filter filter2[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		TRACE_SYSCALL(open),
		TRACE_SYSCALL(openat),
		TRACE_SYSCALL(connect),
		TRACE_SYSCALL(unlink),
		TRACE_SYSCALL(unlinkat),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter2)/sizeof(filter2[0])),
		.filter = filter2,
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
  // logger<<child<<": Wants to open() path: '"<<path<<"'"<<endl;
  if(!path.empty() && path[0]!='/')
    path=getcwdFor(child)+"/"+path;
  cleanupPath(path);
  return path;
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

ComboAddress getPtraceComboAddress(pid_t child, unsigned long long sockaddr, unsigned long long socklen)
{
  ComboAddress ret;

  for(unsigned int i = 0; i < socklen && i < sizeof(ret); ++i) {
    unsigned int c = ptrace(PTRACE_PEEKTEXT, child, sockaddr + i, 0);
    memcpy(((char*)&ret)+i, &c, 1);
  }
  return ret;
}

bool checkNetworkPolicy(const ComboAddress& dest, pid_t child, ofstream& logger)
{
  if(dest.sin4.sin_family == AF_INET || dest.sin4.sin_family == AF_INET6) {
    logger<<child<<": Wants to connect to "<<dest.toStringWithPort()<<endl;
    if(!g_nmg.match(dest)) {
      logger<<child<<": denied connection to to "<<dest.toStringWithPort()<<endl;
      return false;
    }
    if(g_vm.count("allowed-ports") && htons(dest.sin4.sin_port) != g_vm["allowed-ports"].as<int>()) {
      logger<<child<<": denied connection to to "<<dest.toStringWithPort()<<" based on port"<<endl;
      return false;
    }
  }
  return true;

}

bool checkWritePolicy(const string& path, pid_t child, ofstream& logger)
{
  if(g_vm.count("write-allow")) {
    if(boost::starts_with(path, g_vm["write-allow"].as<string>())) {
      return true;
    }
    else
      logger<<child<<": open of '"<<path<<"' denied, did not start with '"<<g_vm["write-allow"].as<string>()<<"' "<<endl;
  }

  if(g_vm["read-only"].as<bool>()) 
    return false;

  return true;
}

int main(int argc, char** argv)
try
{
  processConfig(argc, argv);
  
  pid_t child=fork();
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

      if (regs.orig_rax == __NR_open) {	
        string path = getFullPath(child, regs.rdi);
	
	int mode=regs.rsi & 0xffff;
        logger<<child<<": Wants to open absolute path: '"<<path<<"', mode "<<mode<<endl;

	if((mode & O_WRONLY) || (mode & O_RDWR) || (mode & O_CREAT)) {
	  if(!checkWritePolicy(path, child, logger)) {
	    logger<<child<<": open denied"<<endl;
	    justSayNo(child, regs);
	  }
	}
	
              
      } else if(regs.orig_rax == __NR_openat) {
	logger<<child<<": Openat on fd "<< (int) regs.rdi<<", "<<getcwdForDir(child, regs.rdi)<<endl;
	string path=getFullPathAt(child, regs.rdi, regs.rsi);
	int mode=regs.rsi & 0xffff;

	logger<<child<<": Wants to openat() absolute path: '"<<path<<"', mode "<<regs.rdx<<endl;
	if((mode & O_WRONLY) || (mode & O_RDWR)) {
	  if(!checkWritePolicy(path, child, logger)) {
	    logger<<child<<": openat denied "<<(mode&O_WRONLY) <<", "<<(mode & O_RDWR)<<endl;
	    justSayNo(child, regs);
	  }
	}

      }
      else if(regs.orig_rax == __NR_connect) {
	if(g_vm["no-outbound-network"].as<bool>())
	  justSayNo(child, regs);

	// rdi, rsi, rdx = socket, addressptr, length

	ComboAddress dest=getPtraceComboAddress(child, regs.rsi, regs.rdx);
	if(!checkNetworkPolicy(dest, child, logger)) {
	  justSayNo(child, regs);
	}
      }
      else if(regs.orig_rax ==__NR_unlink ) {
        string path = getFullPath(child, regs.rdi);
	logger<<child<<": wants to delete '"<<path<<"'"<<endl;
	if(!checkWritePolicy(path, child, logger)) {
	  logger<<child<<": unlink denied"<<endl;
	  justSayNo(child, regs);
	}
      }
      else if(regs.orig_rax ==__NR_unlinkat ) {
        string path = getFullPathAt(child, regs.rdi, regs.rsi);
	logger<<child<<": wants to delete '"<<path<<"'"<<endl;
	if(!checkWritePolicy(path, child, logger)) {
	  logger<<child<<": unlinkat denied"<<endl;
	  justSayNo(child, regs);
	}
      }

      else if (regs.orig_rax == __NR_execve || regs.orig_rax == __NR_vfork || regs.orig_rax==__NR_fork) {
	// we get these, but no need to do anything: execve, vfork, fork
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
