/*
 *        File:         test_protocol.c
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Basic twping control server emulation
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>

#include <owamp/owamp.h>
#
#include "./test_protocol.h"

#define SESSION_PORT 0xABCD // not verified 

#define CHALLENGE "just a challenge"
#define SALT "some funny saltT"

// Greeting message [RFC 4656 pg. 6]
struct _greeting {
    uint8_t Unused[12];
    uint32_t Modes;
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint32_t Count;
    uint8_t MBZ[12];
};

// Set-Up-Response message [RFC 4656 pg. 7]
struct _setup_response {
    uint32_t Mode;
    uint8_t KeyID[80];
    uint8_t Token[64];
    uint8_t Client_IV[16];
};

// Server-Start message [RFC 4656 pg. 9]
struct _server_start {
    uint8_t MBZ[15];
    uint8_t Accept;
    uint8_t Server_IV[16];
    uint64_t StartTime;
    uint8_t MBZ2[8];
};

// Request-Session message [RFC 4656 pg. 13]
#pragma pack(push)
#pragma pack(4) // StartTime & Timeout don't fall on dword boundaries
struct _request_session {
    // 00
    uint8_t CommandId;
    union {
        uint8_t MBZ: 4;
        uint8_t IPVN: 4;
    } version;
    uint8_t ConfSender;
    uint8_t ConfReceiver;

    // 04
    uint32_t NumSlots;

    // 08
    uint32_t NumPackets;

    // 12
    uint16_t SenderPort;
    uint16_t ReceiverPort;

    // 16/20/24/28
    uint8_t SenderAddress[4];
    uint8_t SenderAddress1[12];

    // 32/36/40/44
    uint8_t ReceiverAddress[4];
    uint8_t ReceiverAddress2[12];

    // 48/52/56/60
    uint8_t SID[16];

    // 64
    uint32_t PaddingLength;

    // 68/72
    uint64_t StartTime;

    // 76/80
    uint64_t Timeout;

    // 84
    uint32_t TypeP;

    // 88/92
    uint8_t MBZ2[8];

    // 96/100/104/108
    uint8_t HMAC[16];
};
#pragma pack(pop)


// schedule slot description format [RFC 4656 pg. 14]
// these are sent following the Request-Session message
struct _schedule_slot_description {
    uint8_t slot_type;
    uint8_t MBZ[7];
    uint32_t SlotParameter;
};

// hmac sent following a sequence of schedule
// slot descriptions
struct _hmac {
    uint8_t HMAC[16];
};

// Accept-Session message [RFC 4656 pg. 16]
struct _accept_session {
    uint8_t Accept;
    uint8_t MBZ;
    uint16_t Port;
    uint8_t SID[16];
    uint8_t MBZ2[12];
    uint8_t HMAC[16];
};


/*
 * Function:        do_control_setup_server
 *
 * Description:     emulates the server side of the test control protocol 
 *
 * In Args:         void pointer to struct _server_test_params
 *
 * Out Args:
 *
 * Scope:
 * Returns:         0 (i.e. test is finished - server shouldn't accept new clients)
 *
 * Side Effect:
 */
int do_control_setup_server(int s, void *context) {

    struct _server_test_params *test_results
        = (struct _server_test_params *) context;
    test_results->sent_greeting
        = test_results->setup_response_ok
        = test_results->sent_server_start
        = test_results->sent_accept_session
        = test_results->test_complete = 0;

    struct _schedule_slot_description *slots = NULL;

    struct _greeting greeting;
    memset(&greeting, 0, sizeof greeting);
    greeting.Modes = htonl(7);
    memcpy(greeting.Challenge, CHALLENGE, sizeof greeting.Challenge);
    memcpy(greeting.Salt, SALT, sizeof greeting.Salt);
    greeting.Count = htonl(1024);
    test_results->sent_greeting 
        = write(s, &greeting, sizeof greeting) == sizeof greeting;

    struct _setup_response setup_response;
    if(recv(s, &setup_response, sizeof setup_response, MSG_WAITALL) != sizeof setup_response) {
        perror("error reading setup response");
        goto cleanup;
    }

    uint32_t mode = ntohl(setup_response.Mode);
    if (mode != OWP_MODE_OPEN) {
        printf("expected setup response mode == OWP_MODE_OPEN, got: 0x%08x", mode);
        goto cleanup;
    }
    // nothing to check in the other fields in unauthenticated mode
    test_results->setup_response_ok = 1;

    struct _server_start server_start;
    memset(&server_start, 0, sizeof server_start);
    server_start.StartTime = htonll(time(NULL));
    assert(sizeof server_start.Server_IV == sizeof test_results->server_iv); // config sanity
    memcpy(server_start.Server_IV, test_results->server_iv, sizeof server_start.Server_IV);
    test_results->sent_server_start
        = write(s, &server_start, sizeof server_start) == sizeof server_start;
    if (!test_results->sent_server_start) {
        perror("error sending server start response");
        goto cleanup;
    }

    struct _request_session request_session;
    if (recv(s, &request_session, sizeof request_session, MSG_WAITALL) != sizeof request_session) {
        perror("error reading request session message");
        goto cleanup; 
    }

    uint32_t num_slots = ntohl(request_session.NumSlots);
    if (num_slots != test_results->expected_num_test_slots) {
        printf("expected %d test slots, got %d\n",
            test_results->expected_num_test_slots, num_slots);
        goto cleanup;
    }

    uint32_t num_packets = ntohl(request_session.NumPackets);
    if (num_packets != test_results->expected_num_test_packets) {
        printf("expected %d test packets, got %d\n",
            test_results->expected_num_test_packets, num_packets);
        goto cleanup;
    }

    slots = (struct _schedule_slot_description *)
        calloc(num_slots, sizeof(struct _schedule_slot_description));
    size_t slots_num_bytes = num_slots * sizeof(struct _schedule_slot_description);
    if (recv(s, slots, slots_num_bytes, MSG_WAITALL) != slots_num_bytes) {
        perror("error reading slot descriptions");
        goto cleanup;
    }

    if (num_slots) {
        struct _hmac hmac;
        if (recv(s, &hmac, sizeof hmac, MSG_WAITALL) != sizeof hmac) {
            perror("error reading hmac");
            goto cleanup;
        }
    }

    struct _accept_session accept_session;
    memset(&accept_session, 0, sizeof accept_session);
    assert(sizeof accept_session.SID <= sizeof test_results->sid); // config sanity
    memcpy(&accept_session.SID, test_results->sid, sizeof accept_session.SID);
    accept_session.Port = htons(SESSION_PORT);
    if (write(s, &accept_session, sizeof accept_session) != sizeof accept_session) {
        perror("error sending Accept-Session response");
        goto cleanup;
    }

    test_results->sent_accept_session = 1;

    printf("do_server: finished!\n");
    test_results->test_complete = 1;

cleanup:
    if (slots) {
        free(slots);
    }

    return 0;
}



