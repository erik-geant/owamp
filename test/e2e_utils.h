/*
 *        File:         e2e_utils.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  end-to-end process utililities
 */


typedef enum _protocol {OWAMP, TWAMP} PROTOCOL;
int e2e_test(PROTOCOL protocol, const char *authmode);
