/*
 *        File:         owe2e_clear.c
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
 * Description:     launch owping and owampd child processes
 *                  perform a measurement and validate the output
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

    return e2e_test(OWAMP, "O");

}


