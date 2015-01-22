#include <np.h> /* NovaProva library */
#include "../api/libpcp.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

// Test it works
void
test_something (void)
{
    NP_ASSERT_TRUE (1);
}

// Test libpcp functions can be called
void
test_function_call (void)
{
    int ret = -1;

    pcp_mapping_printall ();

    ret = (int) pcp_initialized_set (true); // Will be true or false

    NP_ASSERT_TRUE (ret > -1);
}
