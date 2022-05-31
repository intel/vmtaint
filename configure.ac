AC_INIT([vmtaint], [1.0])
AM_INIT_AUTOMAKE([1.14 foreign subdir-objects])
LT_INIT

AC_CONFIG_SRCDIR(src/vmtaint.cpp)
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIRS([m4])
AM_SANITY_CHECK

AC_PROG_CXX(clang++)
AX_CXX_COMPILE_STDCXX([17], [ext], [mandatory])
AC_LANG(C++)

AC_CHECK_HEADERS([triton/api.hpp], [], [AC_MSG_ERROR(No triton headers found)])

LIBS="$LIBS -ltriton"
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([#include <triton/api.hpp>
                      using namespace triton;],
                     [triton::API api])], [],
        [AC_MSG_ERROR(No triton library found)]
)

PKG_CHECK_MODULES([VMI], [libvmi],[],[AC_MSG_ERROR(LibVMI not found. Install missing package and re-run)])
AC_CHECK_HEADERS([intel-pt.h], [], [AC_MSG_ERROR([intel-pt.h not usable. Install missing package and re-run])])
AC_CHECK_LIB(ipt, pt_insn_set_image, [], [AC_MSG_ERROR([libipt not found])])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
