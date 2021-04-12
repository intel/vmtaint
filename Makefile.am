bin_PROGRAMS = vmtaint
vmtaint_SOURCES = src/vmtaint.cpp
vmtaint_LDADD = $(LIBS) $(VMI_LIBS) -ltriton
vmtaint_LDFLAGS = -Wl,-z,relro -Wl,-z,now
vmtaint_CXXFLAGS = $(CXXFLAGS) $(VMI_CFLAGS) \
                   -fstack-protector-strong \
                   -D_FORTIFY_SOURCE=2 -Wall -Wextra \
                   -Wno-unused-parameter -fno-strict-overflow

ACLOCAL_AMFLAGS=-I m4
EXTRA_DIST = configure.ac Makefile.am README.md COPYING
