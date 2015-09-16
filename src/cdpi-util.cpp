// ClearOS DPI Daemon
// Copyright (C) 2015 ClearFoundation <http://www.clearfoundation.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cstdlib>
#include <cstdarg>

#include <syslog.h>

#include "ndpi_main.h"

using namespace std;

#include "cdpi-util.h"

extern bool cdpi_debug;

void *cdpi_mem_alloc(unsigned long size)
{
    return malloc(size);
}

void cdpi_mem_free(void *ptr)
{
    free(ptr);
}

extern pthread_mutex_t *cdpi_output_mutex;

void cdpi_printf(const char *format, ...)
{
    pthread_mutex_lock(cdpi_output_mutex);

    va_list ap;
    va_start(ap, format);

    if (cdpi_debug)
        vfprintf(stdout, format, ap);
    else
        vsyslog(LOG_DAEMON | LOG_INFO, format, ap);

    va_end(ap);

    pthread_mutex_unlock(cdpi_output_mutex);
}

void cdpi_debug_printf(
    unsigned int i, void *p, ndpi_log_level_t l, const char *format, ...)
{
    if (cdpi_debug) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
