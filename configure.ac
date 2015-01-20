#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([pcp],
        [m4_esyscmd_s([git describe --always --dirty])])

AM_INIT_AUTOMAKE(subdir-objects)

AC_CONFIG_SRCDIR([pcpd/packets_pcp_serialization.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

PKG_CHECK_MODULES([NOVAPROVA],[novaprova],[],[unittest_prereq=no])
PKG_CHECK_MODULES([GLIB],[glib-2.0],[],[unittest_prereq=no])
PKG_CHECK_MODULES([GLIBMM],[glibmm-2.4],[],[unittest_prereq=no])
PKG_CHECK_MODULES([GOBJECT],[gobject-2.0],[],[unittest_prereq=no])
PKG_CHECK_MODULES([LIBXMLXX],[libxml++-2.6],[],[unittest_prereq=no])
PKG_CHECK_MODULES([LIBXML],[libxml-2.0],[],[unittest_prereq=no])
PKG_CHECK_MODULES([SIGCXX],[sigc++-2.0],[],[unittest_prereq=no])

AC_ARG_ENABLE([unittest],
  [AS_HELP_STRING([--enable-unittest],
    [enable unittest code])
  ])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket strrchr])

if test "${enable_unittest}" = "yes"; then
    if test "${unittest_prereq}" = "no"; then
        AC_MSG_ERROR([Unittests requested but prerequisite packages not met])
    fi
fi
AM_CONDITIONAL(HAVE_UNITTEST, [test "$enable_unittest" = "yes"])

#
# check for cross dev root
# default should be prefix
CROSS_DEV_ROOT_DIR=$prefix
AC_ARG_WITH(cross_dev_root_dir,
	[  --with-cross_dev_root_dir=DIR if cross compiling specify the root dev dir],
	[
		CROSS_DEV_ROOT_DIR=$withval
	]
)
AC_SUBST(CROSS_DEV_ROOT_DIR)

AC_OUTPUT(Makefile)
