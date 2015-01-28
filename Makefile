-include sysdeps/$(shell uname).inc
VERSION=0.1

ifeq ($(CXX),clang++)
	CXX2011FLAGS=-std=c++11 -stdlib=libc++
endif

CXXFLAGS?=-Wall -O3 -ggdb -I. -MMD -MP -DHAVE_LINUX_SECCOMP_H $(CXX2011FLAGS)
CFLAGS=-Wall -I.  -O3 -MMD -MP -DHAVE_LINUX_SECCOMP_H
LDFLAGS+=$(CXX2011FLAGS) -pthread  $(STATICFLAGS) 
CHEAT_ARG := $(shell ./update-git-hash-if-necessary)

SHIPPROGRAMS=secfilt testing
PROGRAMS=$(SHIPPROGRAMS) 

all: $(PROGRAMS)

-include *.d

.PHONY:	check

secfilt: secfilt.o  iputils.o 
	$(CC) $^ $(LDFLAGS) -o $@

testing: testing.o  
	$(CC) $^ $(LDFLAGS) -o $@


syscall-names.h: /usr/include/syscall.h 
	echo "static const char *syscall_names[] = {" > $@ ;\
	echo "#include <syscall.h>" | cpp -dM | grep '^#define __NR_' | \
	LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([0-9]+)(.*)/ [\2] = "\1",/p' >> $@ ;\
	echo "};" >> $@

syscall-reporter.o: syscall-reporter.c syscall-names.h

clean:
	rm -f *~ *.o *.d $(PROGRAMS) githash.h 

package: all
	rm -rf dist
	DESTDIR=dist make install
	fpm -s dir -f -t rpm -n metronome -v 1.g$(shell cat githash) -C dist .
	fpm -s dir -f -t deb -n metronome -v 1.g$(shell cat githash) -C dist .	
	rm -rf dist

check: testrunner
	./testrunner

testrunner: testrunner.o test-statstorage.o statstorage.o
	$(CXX) $^ -lboost_unit_test_framework -o $@ 
