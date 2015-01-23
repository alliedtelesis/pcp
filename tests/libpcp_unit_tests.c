#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int
set_up (void)
{
    system ("apteryxd -b");
    pcp_init ();
    return 0;
}

// Test it works
void
test_something (void)
{
    NP_ASSERT_TRUE (1);
}

// Test pcp_initialized set and get
void
test_pcp_initialized_set_get (void)
{
    NP_ASSERT_TRUE (pcp_initialized_set (true));
    NP_ASSERT_EQUAL (pcp_initialized_get (), true);

    NP_ASSERT_TRUE (pcp_initialized_set (false));
    NP_ASSERT_EQUAL (pcp_initialized_get (), false);
}

// Test pcp_enabled set and get
void
test_pcp_enabled_set_get (void)
{
    NP_ASSERT_TRUE (pcp_enabled_set (true));
    NP_ASSERT_EQUAL (pcp_enabled_get (), true);

    NP_ASSERT_TRUE (pcp_enabled_set (false));
    NP_ASSERT_EQUAL (pcp_enabled_get (), false);
}

int
tear_down (void)
{
    pcp_deinit_hard ();
    system ("pkill apteryxd");
    return 0;
}
