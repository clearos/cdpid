#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <cstdlib>

#include "ndpi_main.h"

using namespace std;

#define NDPI_DETECTION_TICKS	1000

static void *cdpi_mem_alloc(unsigned long size)
{
	return malloc(size);
}

static void cdpi_mem_free(void *ptr)
{
	free(ptr);
}

int main(int argc, char *argv[])
{
	struct ndpi_detection_module_struct *ndpi = NULL;

	ndpi = ndpi_init_detection_module(
		NDPI_DETECTION_TICKS,
		cdpi_mem_alloc,
		cdpi_mem_free,
		NULL);

	NDPI_PROTOCOL_BITMASK proto_all;
	NDPI_BITMASK_SET_ALL(proto_all);
	ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);

	cout << "cDPId v" << PACKAGE_VERSION << endl;

	return 0;
}
