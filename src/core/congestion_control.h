/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "cubic.h"

typedef struct QUIC_ACK_EVENT {

    uint64_t TimeNow; // microsecond

    uint64_t LargestAck;

    uint64_t LargestSentPacketNumber;

    //
    // Number of retransmittable bytes acked during the connection's lifetime
    //
    uint64_t NumTotalAckedRetransmittableBytes;

    QUIC_SENT_PACKET_METADATA* AckedPackets;

    uint32_t NumRetransmittableBytes;

    //
    // Connection's current SmoothedRtt.
    //
    uint32_t SmoothedRtt;

    //
    // The smallest calculated RTT of the packets that were just ACKed.
    //
    uint32_t MinRtt;

    //
    // Acked time minus ack delay.
    //
    uint32_t AdjustedAckTime;

    BOOLEAN IsImplicit : 1;

    BOOLEAN HasLoss : 1;

    BOOLEAN IsLargestAckedPacketAppLimited : 1;

    BOOLEAN MinRttValid : 1;

} QUIC_ACK_EVENT;

typedef struct QUIC_LOSS_EVENT {

    uint64_t LargestPacketNumberLost;

    uint64_t LargestSentPacketNumber;

    uint32_t NumRetransmittableBytes;

    BOOLEAN PersistentCongestion : 1;

} QUIC_LOSS_EVENT;

typedef struct QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY {

    uint64_t Value;

    uint64_t Time;

} QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY;


typedef struct QUIC_SLIDING_WINDOW_EXTREMUM {

    //
    // Lifetime of each entry
    //
    uint64_t EntryLifetime;

    //
    // Capcity of sliding window
    //
    uint32_t WindowCapacity;

    //
    // Current size of sliding window
    //
    uint32_t WindowSize;
    
    //
    // Head of the monotone queue
    //
    uint32_t WindowHead;

    //
    // Rotated monotone deque maintains the extremum of sliding window
    //
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY* Extremums;

} QUIC_SLIDING_WINDOW_EXTREMUM;

#define kBbrDefaultFilterCapacity 3

typedef struct BBR_BANDWIDTH_FILTER {

    //
    // TRUE if bandwidth is limited by the application
    //
    BOOLEAN AppLimited : 1;

    //
    // Target packet number to quit the AppLimited state
    //
    uint64_t AppLimitedExitTarget;

    //
    // Max filter for tracking the maximum recent delivery_rate sample, for estimating max bandwidth
    //
    QUIC_SLIDING_WINDOW_EXTREMUM WindowedMaxFilter;

    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY WindowedMaxFilterEntries[kBbrDefaultFilterCapacity];

} BBR_BANDWIDTH_FILTER;

typedef struct QUIC_CONGESTION_CONTROL_BBR {

    //
    // Whether the bottleneck bandwidth has been detected
    //
    BOOLEAN BtlbwFound : 1;

    //
    // TRUE when exiting quiescence
    //
    BOOLEAN ExitingQuiescence : 1;

    //
    // If TRUE, EndOfRecovery is valid
    //
    BOOLEAN EndOfRecoveryValid : 1;

    //
    // If TRUE, EndOfRoundTrip is valid
    //
    BOOLEAN EndOfRoundTripValid : 1;

    //
    // If TRUE, AckAggregationStartTime is valid
    //
    BOOLEAN AckAggregationStartTimeValid : 1;

    //
    // If TRUE, ProbeRttRound is valid
    //
    BOOLEAN ProbeRttRoundValid : 1;

    //
    // If TRUE, ProbeRttEndTime is valid
    //
    BOOLEAN ProbeRttEndTimeValid : 1;

    //
    // If TRUE, current RTT sample is expired
    //
    BOOLEAN RttSampleExpired: 1;

    //
    // If TRUE, there has been at least one MinRtt sample
    //
    BOOLEAN MinRttTimestampValid: 1;
    
    //
    // The size of the initial congestion window in packets
    //
    uint32_t InitialCongestionWindowPackets;

    uint32_t CongestionWindow; // bytes

    uint32_t InitialCongestionWindow; // bytes

    uint32_t RecoveryWindow; // bytes

    //
    // The number of bytes considered to be still in the network.
    //
    // The client of this module should send packets until BytesInFlight becomes
    // larger than CongestionWindow (see QuicCongestionControlCanSend). This
    // means BytesInFlight can become larger than CongestionWindow by up to one
    // packet's worth of bytes, plus exemptions (see Exemptions variable).
    //
    uint32_t BytesInFlight;
    uint32_t BytesInFlightMax;

    //
    // A count of packets which can be sent ignoring CongestionWindow.
    // The count is decremented as the packets are sent. BytesInFlight is still
    // incremented for these packets. This is used to send probe packets for
    // loss recovery.
    //
    uint8_t Exemptions;

    //
    // Count of packet-timed round trips
    //
    uint64_t RoundTripCounter;

    //
    // The dynamic gain factor used to scale the estimated BDP to produce a
    // congestion window (cwnd)
    //
    uint32_t CwndGain;

    //
    // The dynamic gain factor used to scale bottleneck bandwidth to produce the
    // pacing rate
    //
    uint32_t PacingGain;

    //
    // The dynamic send quantum specifies the maximum size of these transmission
    // aggregates
    //
    uint64_t SendQuantum;

    //
    // Counter of continuous round trips in STARTUP
    //
    uint8_t SlowStartupRoundCounter;

    //
    // Current cycle index in kPacingGain
    //
    uint32_t PacingCycleIndex;

    //
    // Starting time of ack aggregation
    //
    uint64_t AckAggregationStartTime;

    //
    // Number of bytes acked during this aggregation
    //
    uint64_t AggregatedAckBytes;

    //
    // Current state of recovery
    //
    uint32_t RecoveryState;

    //
    // Current state of BBR state machine
    //
    uint32_t BbrState;

    //
    // The time at which the last pacing gain cycle was started
    //
    uint64_t CycleStart;

    //
    // Receiving acknowledgement of a packet after EndoOfRoundTrip will
    // indicate the current round trip is ended
    //
    uint64_t EndOfRoundTrip;

    //
    // Receiving acknowledgement of a packet after EndoOfRecovery will cause
    // BBR to exit the recovery mode
    //
    uint64_t EndOfRecovery;

    //
    // The bandwidth of last during STARTUP state
    //
    uint64_t LastEstimatedStartupBandwidth;

    //
    // Indicates whether to exit ProbeRtt if there're at least one RTT round with the
    // minimum cwnd
    //
    uint64_t ProbeRttRound;

    //
    // Indicates the eariest time to exit ProbeRTT state
    //
    uint64_t ProbeRttEndTime;

    //
    // The max filter tracking the recent maximum degree of aggregation in the path
    //
    QUIC_SLIDING_WINDOW_EXTREMUM MaxAckHeightFilter;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY MaxAckHeightFilterEntries[kBbrDefaultFilterCapacity];

    uint32_t MinRtt; // microseconds

    //
    // Time when MinRtt was sampled. Only valid if MinRttTimestampValid is set.
    //
    uint64_t MinRttTimestamp; // microseconds

    //
    // BBR estimates maximum bandwidth by the maximum recent bandwidth
    //
    BBR_BANDWIDTH_FILTER BandwidthFilter;

} QUIC_CONGESTION_CONTROL_BBR;

typedef struct QUIC_CONGESTION_CONTROL {

    //
    // Name of congestion control algorithm
    //
    const char* Name;

    BOOLEAN (*QuicCongestionControlCanSend)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlSetExemption)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint8_t NumPackets
        );

    void (*QuicCongestionControlReset)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ BOOLEAN FullReset
        );

    uint32_t (*QuicCongestionControlGetSendAllowance)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint64_t TimeSinceLastSend,
        _In_ BOOLEAN TimeSinceLastSendValid
        );

    void (*QuicCongestionControlOnDataSent)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint32_t NumRetransmittableBytes
        );

    BOOLEAN (*QuicCongestionControlOnDataInvalidated)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ uint32_t NumRetransmittableBytes
        );

    BOOLEAN (*QuicCongestionControlOnDataAcknowledged)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ const QUIC_ACK_EVENT* AckEvent
        );

    void (*QuicCongestionControlOnDataLost)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc,
        _In_ const QUIC_LOSS_EVENT* LossEvent
        );

    BOOLEAN (*QuicCongestionControlOnSpuriousCongestionEvent)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlLogOutFlowStatus)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint8_t (*QuicCongestionControlGetExemptions)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint32_t (*QuicCongestionControlGetBytesInFlightMax)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    uint32_t (*QuicCongestionControlGetCongestionWindow)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    BOOLEAN (*QuicCongestionControlIsAppLimited)(
        _In_ const struct QUIC_CONGESTION_CONTROL* Cc
        );

    void (*QuicCongestionControlSetAppLimited)(
        _In_ struct QUIC_CONGESTION_CONTROL* Cc
        );

    //
    // Algorithm specific state.
    //
    union {
        QUIC_CONGESTION_CONTROL_CUBIC Cubic;
        QUIC_CONGESTION_CONTROL_BBR Bbr;
    };

} QUIC_CONGESTION_CONTROL;

//
// Initializes the algorithm specific congestion control algorithm.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );

//
// Returns TRUE if more bytes can be sent on the network.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlCanSend(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlCanSend(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlSetExemption(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint8_t NumPackets
    )
{
    Cc->QuicCongestionControlSetExemption(Cc, NumPackets);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlReset(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ BOOLEAN FullReset
    )
{
    Cc->QuicCongestionControlReset(Cc, FullReset);
}

//
// Returns the number of bytes that can be sent immediately.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetSendAllowance(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint64_t TimeSinceLastSend, // microsec
    _In_ BOOLEAN TimeSinceLastSendValid
    )
{
    return Cc->QuicCongestionControlGetSendAllowance(Cc, TimeSinceLastSend, TimeSinceLastSendValid);
}

//
// Called when any retransmittable data is sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
QuicCongestionControlOnDataSent(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    Cc->QuicCongestionControlOnDataSent(Cc, NumRetransmittableBytes);
}

//
// Called when any data needs to be removed from inflight but cannot be
// considered lost or acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnDataInvalidated(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ uint32_t NumRetransmittableBytes
    )
{
    return Cc->QuicCongestionControlOnDataInvalidated(Cc, NumRetransmittableBytes);
}

//
// Called when any data is acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnDataAcknowledged(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_ACK_EVENT* AckEvent
    )
{
    return Cc->QuicCongestionControlOnDataAcknowledged(Cc, AckEvent);
}

//
// Called when data is determined lost.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlOnDataLost(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_LOSS_EVENT* LossEvent
    )
{
    Cc->QuicCongestionControlOnDataLost(Cc, LossEvent);
}

//
// Called when all recently considered lost data was actually acknowledged.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlOnSpuriousCongestionEvent(
    _In_ QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlOnSpuriousCongestionEvent(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint8_t
QuicCongestionControlGetExemptions(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetExemptions(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlLogOutFlowStatus(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->QuicCongestionControlLogOutFlowStatus(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetBytesInFlightMax(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetBytesInFlightMax(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
QuicCongestionControlGetCongestionWindow(
    _In_ const QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlGetCongestionWindow(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
BOOLEAN
QuicCongestionControlIsAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    return Cc->QuicCongestionControlIsAppLimited(Cc);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
void
QuicCongestionControlSetAppLimited(
    _In_ struct QUIC_CONGESTION_CONTROL* Cc
    )
{
    Cc->QuicCongestionControlSetAppLimited(Cc);
}
