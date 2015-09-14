AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CXXFLAGS = ${CXXFLAGS} -std=gnu++11 -I../include -I../ndpi/src/include

#EXTRA_DIST = 

sbin_PROGRAMS = cdpid
cdpid_SOURCES = cdpid.cpp cdpi-thread.cpp cdpi-util.cpp
cdpid_LDADD = ../ndpi/src/lib/libndpi.la

