/*
 *        File:         test_protocol.h
 *
 *        Author:       Erik Reid
 *                      GÉANT
 *
 *        Description:  Control protocol message structures, cf. RFC 4656
 */


// Greeting message [RFC pg. 6]
struct _greeting {
    uint8_t Unused[12];
    uint8_t Modes[4];
    uint8_t Challenge[16];
    uint8_t Salt[16];
    uint8_t Count[4];
    uint8_t MBZ[12];
};

// Set-Up-Response message [RFC pg. 7]
struct _setup_response {
    uint8_t Mode[4];
    uint8_t KeyID[80];
    uint8_t Token[64];
    uint8_t Client_IV[16];
};

// Server-Start message [RFC pg. 9]
struct _server_start {
    uint8_t MBZ[15];
    uint8_t Accept;
    uint8_t Server_IV[16];
    uint64_t StartTime;
    uint8_t MBZ2[8];
};

// Request-Session message [RFC pg. 13]
struct _request_session {
    uint8_t CommandId;
    union {
        uint8_t MBZ: 4;
        uint8_t IPVN: 4;
    } version;
    uint8_t ConfSender;
    uint8_t ConfReceiver;
    uint32_t NumSlots;
    uint32_t NumPackets;
    uint16_t SenderPort;
    uint16_t ReceiverPort;
    uint8_t SenderAddress[4];
    uint8_t SenderAddress1[12];
    uint8_t ReceiverAddress[4];
    uint8_t ReceiverAddress2[12];
    uint8_t SID[16];
    uint32_t PaddingLength;
    uint64_t StartTime;
    uint64_t Timeout;
    uint32_t TypeP;
    uint8_t MBZ2[8];
    uint8_t HMAC[16];
};

// schedule slot description format [RFC pg. 14]
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

// Accept-Session message [RFC pg. 16]
struct _accept_session {
    uint8_t Accept;
    uint8_t MBZ;
    uint16_t Port;
    uint8_t SID[16];
    uint8_t MBZ2[12];
    uint8_t HMAC[16];
};

