AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([gsstunnel],
        VERSION_NUMBER,
        [simo@redhat.com])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
AC_PROG_CC_C99
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT([disable-static])
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14])

AC_SUBST([PRERELEASE_VERSION],
         PRERELEASE_VERSION_NUMBER)

AC_DEFINE([PRERELEASE_VERSION], "PRERELEASE_VERSION_NUMBER",
          [Prerelease version number of package])

AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 &>/dev/null])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

#Include here cause WITH_INIT_DIR requires $osname set in platform.m4
m4_include([external/platform.m4])

m4_include(conf_macros.m4)
WITH_DISTRO_VERSION
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG

m4_include([external/pkg.m4])
m4_include([external/libpopt.m4])
m4_include([external/docbook.m4])
m4_include([external/sizes.m4])

AC_CHECK_HEADERS([gssapi/gssapi.h],,[AC_MSG_ERROR([Could not find GSSAPI headers])])
AC_PATH_PROG(KRB5_CONFIG, krb5-config, failed)
if test x$KRB5_CONFIG = xfailed; then
    AC_MSG_ERROR([Could not find GSSAPI development libraries])
else
    GSSAPI_CFLAGS="`$KRB5_CONFIG --cflags gssapi`"
    GSSAPI_LIBS="`$KRB5_CONFIG --libs gssapi`"
fi
AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

#Check for libini_config
PKG_CHECK_MODULES([LIBINI_CONFIG], [ini_config >= 1.0.0], [have_libini_config=1], [have_libini_config=])
if test x$have_libini_config = x; then
    AC_MSG_ERROR([Could not find LIBINI_CONFIG headers])
else
    INI_CFLAGS="`$PKG_CONFIG --cflags ini_config`"
    INI_LIBS="`$PKG_CONFIG --libs ini_config`"
    AC_CHECK_LIB(ini_config, ini_config_file_open, [],
                 [AC_MSG_WARN([ini_config library must support ini_config_file_open])],
                 [$INI_LIBS])
fi
AC_SUBST(INI_LIBS)
AC_SUBST(INI_CFLAGS)

if test x$HAVE_NLS != x; then
    AC_CHECK_FUNC(dgettext, [],
                  AC_CHECK_LIB(intl, dgettext, [],
                               AC_ERROR([Could not find dgettext() function])))
    AC_PATH_PROG(MSGFMT, msgfmt)
    if test x$MSGFMT = x; then
        AC_ERROR([Could not find msgfmt])
    fi
fi
RAWLINGUAS=`sed -e "/^#/d" -e "s/#.*//" "${srcdir}/po/LINGUAS"`
# Remove newlines
LINGUAS=`echo $RAWLINGUAS`
AC_SUBST(LINGUAS)

if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                     [Docbook XSL templates])
    AC_CHECK_PROG([PO4A],[po4a],[po4a],[no])
fi
AM_CONDITIONAL([HAVE_MANPAGES], [test "x$HAVE_MANPAGES" != "x"])
AM_CONDITIONAL([HAVE_PO4A], [test "x$PO4A" != "xno"])

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

AC_CONFIG_FILES([Makefile man/Makefile po/Makefile
                 contrib/gsstunnel.spec])
AC_OUTPUT
