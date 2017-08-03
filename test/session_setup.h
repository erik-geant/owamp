/*
 *        File:         session_setup.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  declarations for use with setup_session.c
 */


OWPBoolean (*PPCB)(
    OWPContext, const OWPUserID, uint8_t**, size_t*, void**, OWPErrSeverity*);

PPCB default_passphrase_callback;

OWPControl (*XWPControlOpen)(
    OWPContext, const char *, I2Addr, uint32_t, OWPUserID, OWPNum64*, OWPErrSeverity*);

