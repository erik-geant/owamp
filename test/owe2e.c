/*
 *        File:         owe2e.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Basic twping client control setup test in clear mode
 */
#include "./e2e_utils.h"

/*
 * Function:        main
 *
 * Description:     launch a simulated twamp server & send commands
 *                  so they can be validated in do_control_setup_server
 *
 * In Args:         argc, argv (unused)
 *
 * Out Args:
 *
 * Scope:           unit test (run using make check)
 * Returns:         non-zero in case of error
 * Side Effect:
 */
int
main(
        int argc __attribute__((unused)),
        char    **argv
    ) {

    return e2e_test();

}


