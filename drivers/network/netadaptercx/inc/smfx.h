/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     State machine framework the generated NetAdapterCx state machines run on
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#pragma once

#include <stdint.h>

#define SMFX_VER 2

namespace SmFx
{

typedef uint16_t EventIndex;
typedef uint16_t EventId;
typedef uint16_t StateIndex;
typedef uint16_t StateId;
typedef uint8_t SubmachineIndex;
typedef void const * StateSlot;

enum class EventQueueingDisposition : uint16_t
{
    Invalid = 0,
    Unlimited = 1,
    KeepLatestOnly = 2,
    KeepOldestOnly = 3,
};

enum class StateFlags : uint8_t
{
    None = 0,
    RequiresPassiveLevel = 1,
    RequiresDedicatedThread = 2,
};

DEFINE_ENUM_FLAG_OPERATORS(StateFlags);

enum class InternalTransitionFlags : uint8_t
{
    None = 0,
    RequiresPassiveLevel = 1,
    RequiresDedicatedThread = 2,
};

DEFINE_ENUM_FLAG_OPERATORS(InternalTransitionFlags);

enum class StateType : uint8_t
{
    Invalid = 0,
    Sync = 1,
    Async = 2,
    Call = 3,
};

enum class StateSlotType : uint16_t
{
    None = 0,
    EntryFunction = 1,
    ExternalTransitions = 2,
    InternalTransitions = 4,
    DeferredEvents = 8,
    PopTransitions = 16,
    PurgeEvents = 32,
    StopTimerOnExit = 64,
};

DEFINE_ENUM_FLAG_OPERATORS(StateSlotType);

enum class MachineException : uint32_t
{
    None = 0,
    UnhandledEvent = 1,
    EventQueueOverflow = 2,
    StackOverflow = 3,
};

enum class TransitionType : uint32_t
{
    Invalid = 0,
    External = 1,
    Internal = 2,
    ExplicitPop = 3,
    ImplicitPop = 4,
    Call = 5,
    Ignore = 6,
    Purge = 7,
};

enum class StopTimerResult : uint32_t
{
    Invalid = 0,
    TimerStopped = 1,
    WaitForTimerFiredEventAndIgnoreIt = 2,
};

typedef EventIndex StateEntryFunction(void * context);
typedef void InternalTransitionAction(void * context);
typedef StopTimerResult StopTimerFunction(void * context);

typedef void EvtLogMachineExceptionFunc(
    void * context,
    MachineException exception,
    EventId relevantEvent,
    StateId relevantState);

typedef void EvtLogEventEnqueueFunc(
    void * context,
    EventId relevantEvent);

typedef void EvtLogTransitionFunc(
    void * context,
    TransitionType transitionType,
    StateId sourceState,
    EventId processedEvent,
    StateId targetState);

typedef void EvtMachineDestroyedFunc(
    void * context);

struct EVENT_SPECIFICATION
{
    EventId id;
    EventQueueingDisposition queueingDisposition;
};

struct EXTERNAL_TRANSITION
{
    EventIndex triggeringEventIndex;
    StateIndex targetStateIndex;
};

struct INTERNAL_TRANSITION
{
    EventIndex triggeringEventIndex;
    InternalTransitionFlags flags;
    InternalTransitionAction * action;
};

struct POP_TRANSITION
{
    EventIndex triggeringEventIndex;
    EventIndex returnEventIndex;
};

struct STOP_TIMER_ON_EXIT_DETAILS
{
    EventIndex timerFiredEvent;
    StopTimerFunction * stopTimerFunction;
};

struct SUBMACHINE_SPECIFICATION
{
    StateIndex initialStateIndex;
};

struct STATE_SPECIFICATION
{
    StateId id;
    StateFlags flags;
    StateType type;
    StateSlotType activeSlots;
    SubmachineIndex callSubmachine;
    StateSlot const * slots;
};

struct STATE_MACHINE_SPECIFICATION
{
    SubmachineIndex mainMachine;
    EventIndex defaultSyncEvent;
    SUBMACHINE_SPECIFICATION const * machineTable;
    EVENT_SPECIFICATION const * eventTable;
    STATE_SPECIFICATION const * stateTable;
};

struct STATE_MACHINE_ENGINE_CONFIG
{
    STATE_MACHINE_SPECIFICATION const * machineSpec;
    void * context;
    PDEVICE_OBJECT deviceObject;
    uint32_t poolTag;
    EvtLogMachineExceptionFunc * logExceptionCallback;
    EvtLogEventEnqueueFunc * logEventEnqueueCallback;
    EvtLogTransitionFunc * logTransitionCallback;
    EvtMachineDestroyedFunc * machineDestroyedCallback;
    bool isWorkerRequired;
    uint8_t stackSize;
};

class StateMachineEngine
{
public:

    StateMachineEngine() = default;

    ~StateMachineEngine();

    StateMachineEngine(StateMachineEngine const &) = delete;

    StateMachineEngine &
    operator=(StateMachineEngine const &) = delete;

    _Must_inspect_result_
    _IRQL_requires_max_(DISPATCH_LEVEL)
    NTSTATUS
    Initialize(
        _In_ STATE_MACHINE_ENGINE_CONFIG const & config);

    bool
    IsInitialized() const;

    _IRQL_requires_max_(DISPATCH_LEVEL)
    void
    EnqueueEvent(
        _In_ EventIndex eventIndex);

    class StateMachineEngineImpl;

private:

    StateMachineEngineImpl * m_impl = nullptr;
};

} // namespace SmFx
