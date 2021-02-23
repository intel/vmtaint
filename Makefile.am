bin_PROGRAMS = vmtaint
vmtaint_SOURCES = src/vmtaint.cpp
vmtaint_LDADD = $(LIBS) $(VMI_LIBS) -ltriton
vmtaint_CXXFLAGS = $(CXXFLAGS) $(VMI_CFLAGS) \
                   -Wall -Wextra -Wno-unused-parameter

ACLOCAL_AMFLAGS=-I m4
EXTRA_DIST = configure.ac Makefile.am README.md COPYING
