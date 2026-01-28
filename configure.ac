# configure.ac for sniffit
# Copyright 1997-1998 Brecht Claerhout
# Copyright 2016-2020 Joao Eriberto Mota Filho <eriberto@eriberto.pro.br.
# Copyright 2024      Denis Ovsienko <denis@ovsienko.info>
# Under BSD-3-CLause license.

AC_PREREQ([2.69])
AC_INIT([sniffit], [0.7], [https://github.com/resurrecting-open-source-projects/sniffit/issues])
AC_CONFIG_SRCDIR([src/sn_generation.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for pcap.
AC_CHECK_LIB([pcap], [pcap_open_live], [], [AC_MSG_ERROR([Couldn't find libpcap])])
AC_CHECK_HEADERS([pcap.h], , AC_MSG_ERROR([pcap.h not found]))

dnl exit function check
AC_CHECK_FUNCS(atexit)

# Other checks
# On Haiku sendto(), socket(), setservent() and inet_addr() are in libnetwork.
AC_CHECK_FUNC(setservent, ,
	[
		AC_CHECK_LIB(network,
			setservent,
			[LIBS="-lnetwork $LIBS"],
			[AC_MSG_ERROR([setservent() is required, but wasn't found])]
		)
	]
)

dnl Check the datalength
AC_CHECK_SIZEOF(unsigned short int)
if test $ac_cv_sizeof_unsigned_short_int -ne 2; then
    AC_MSG_ERROR([unsigned short is NOT 2 bytes... quiting])
fi

AC_CHECK_SIZEOF(unsigned long int)
if test $ac_cv_sizeof_unsigned_long_int -eq 4; then
AC_DEFINE(USE_32_LONG_INT, 1, [none])
else
    echo "unsigned long is NOT 4 bytes... hmmm..."
    AC_CHECK_SIZEOF(unsigned int)
    if test $ac_cv_sizeof_unsigned_int -ne 4; then
        AC_MSG_ERROR([unsigned int is NOT 4 bytes either... quiting])
    else
        AC_DEFINE(USE_32_INT, 1, [none])
    fi
fi

AC_MSG_CHECKING([is IRIX platform])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #ifdef __sgi
    /* IRIX Macro from github:cpredef/predef/OperatingSystems.md#L314 */
    #else
    #error Not IRIX Platform
    #endif
]])], [
    enable_interface=no
    AC_MSG_RESULT([yes])
    AC_MSG_NOTICE([Interactive interface is not supported on IRIX])
], [
    enable_interface=yes
    AC_MSG_RESULT([no])
])
AC_MSG_CHECKING([is BSDI platform])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #ifdef __bsdi__
    /* BSDI Macro from github:cpredef/predef/OperatingSystems.md#L103 */
    #else
    #error Not BSDI Platform
    #endif
]])], [
    enable_interface=no
    AC_MSG_RESULT([yes])
    AC_MSG_NOTICE([Interactive interface is not supported on BSDI])
], [
    AC_MSG_RESULT([no])
])

dnl Check Shared Memory support
AC_CHECK_FUNCS(shmget)
if test "$ac_cv_func_shmget" != yes; then
    enable_interface=no
    AC_MSG_NOTICE([The interactive interface requires shared memory functionality])
fi

dnl Find ncurses.h and link ncurses only if all other checks pass
if test "$enable_interface" = yes; then
    # Checks for ncurses
    AC_CHECK_HEADERS([ncurses.h], [
        dnl Have header so we can now check for ncurses library
        AC_CHECK_LIB([ncurses], [initscr], [], [
            enable_interface=no
            AC_MSG_NOTICE([The interactive interface requires ncurses library])
        ])
    ], [
        enable_interface=no
        AC_MSG_NOTICE([The interactive interface requires ncurses.h header])
    ])
fi

dnl Define INCLUDE_INTERFACE or not
if test "$enable_interface" = yes; then
    AC_DEFINE(INCLUDE_INTERFACE, 1, [Define to 1 to enable interactive interface])
    AC_MSG_NOTICE([Interactive interface: Enabled])
else
    AC_MSG_NOTICE([Interactive interface: Disabled])
fi

AC_CONFIG_FILES([Makefile src/Makefile])
AM_INIT_AUTOMAKE([foreign])

AC_OUTPUT
