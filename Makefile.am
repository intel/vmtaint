bin_PROGRAMS = vmtaint
vmtaint_SOURCES = src/taint.cpp
vmtaint_LDADD = $(LIBS) $(VMI_LIBS) -ltriton
vmtaint_CXXFLAGS = $(CXXFLAGS) $(VMI_CFLAGS)

ACLOCAL_AMFLAGS=-I m4
EXTRA_DIST = configure.ac Makefile.am README.md COPYING
