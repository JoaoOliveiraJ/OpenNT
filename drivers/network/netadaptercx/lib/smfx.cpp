/*
 * PROJECT:     OpenNT NetAdapterCx
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Engine that runs the generated NetAdapterCx state machines
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif193.001@gmail.com>
 */

#include <ntosp.h>
#include <knew.h>
#include <smfx.h>

namespace SmFx
{

static constexpr uint32_t DefaultPoolTag = 'xFmS';
static constexpr uint8_t DefaultStackSize = 16;
static constexpr uint8_t EventQueueLength = 16;
static constexpr uint8_t EventQueueMask = EventQueueLength - 1;
static constexpr uint8_t ExceptionHistoryLength = 8;
static constexpr uint8_t TransitionHistoryLength = 64;
static constexpr uint8_t NoStackDepth = 0xFF;

enum class EngineState : uint32_t
{
    Invalid = 0,
    Stopped = 1,
    Running = 2,
    WaitingForWorkerStateEntry = 3,
    WaitingForWorkerEventAction = 4,
    WaitingForTimerFiredEvent = 5,
};

enum class EventAction : uint32_t
{
    Invalid = 0,
    NoAction = 1,
    ExternalTransition = 2,
    InternalTransition = 3,
    PopTransition = 4,
    Defer = 5,
    CallTransition = 6,
};

struct EVENT_ACTION
{
    EventAction action;
    EventIndex eventIndex;
    uint8_t stackDepth;
    void const * entry;
};

struct EXCEPTION_RECORD_ENTRY
{
    MachineException exception;
    EventIndex relevantEvent;
    StateIndex relevantState;
};

struct TRANSITION_RECORD_ENTRY
{
    TransitionType transitionType;
    EventIndex processedEvent;
    StateIndex stateIndex;
    uint8_t stackDepth;
};

class StateMachineEngine::StateMachineEngineImpl
{
public:

    StateMachineEngineImpl(
        _In_ StateMachineEngineImpl ** OwnerPointer) :
        m_ownerPointer(OwnerPointer)
    {
        KeInitializeSpinLock(&m_lock);
    }

    NTSTATUS
    Initialize(
        _In_ STATE_MACHINE_ENGINE_CONFIG const & Config);

    void
    InitiateFirstRun(
        void);

    void
    EnqueueEvent(
        _In_ EventIndex Event);

    void
    Destroy(
        _In_ bool NotifyOwner);

private:

    void
    AcquireLock(
        void)
    {
        KIRQL irql;
        KeAcquireSpinLock(&m_lock, &irql);
        m_lockIrql = irql;
    }

    void
    ReleaseLock(
        void)
    {
        KeReleaseSpinLock(&m_lock, m_lockIrql);
    }

    StateIndex
    CurrentState(
        void) const
    {
        return m_numStatesOnStack == 0 ? 0 : m_stack[m_numStatesOnStack - 1];
    }

    STATE_SPECIFICATION const &
    State(
        _In_ StateIndex Index) const
    {
        return m_config.machineSpec->stateTable[Index];
    }

    void const *
    Slot(
        _In_ StateIndex Index,
        _In_ StateSlotType Type) const;

    void
    MarkRunning(
        _In_ KIRQL Irql,
        _In_ bool DedicatedThread)
    {
        m_runningIrql = Irql;
        m_isRunningOnDedicatedThread = DedicatedThread;
    }

    bool
    CanRunOnCurrentContext(
        _In_ bool RequiresPassiveLevel,
        _In_ bool RequiresDedicatedThread) const
    {
        return (!RequiresDedicatedThread || m_isRunningOnDedicatedThread) &&
               (!RequiresPassiveLevel || m_runningIrql == PASSIVE_LEVEL);
    }

    bool
    EnqueueEventWithDisposition(
        _In_ EventIndex Event);

    bool
    AddEventToEventQueue(
        _In_ EventIndex Event);

    void
    FindActionForEvent(
        _In_ EventIndex Event,
        _Out_ EVENT_ACTION & Action) const;

    EngineState
    ExecuteEventAction(
        _Inout_ EVENT_ACTION & Action);

    EngineState
    ExecuteCurrentState(
        void);

    EngineState
    ExitCurrentState(
        _In_ EVENT_ACTION const & Action);

    EngineState
    PopToStackDepth(
        _In_ EVENT_ACTION const & Action);

    void
    ProcessEventQueue(
        _In_ bool ResumeAfterTimer);

    void
    UpdateEngineState(
        _In_ EngineState NewState);

    void
    SaveResumeAction(
        _In_ EVENT_ACTION const & Action)
    {
        m_resumeAction = Action;
    }

    void
    ReportException(
        _In_ MachineException Exception,
        _In_ EventIndex Event,
        _In_ StateIndex State,
        _In_ bool LockHeld);

    void
    LogTransition(
        _In_ TransitionType Type,
        _In_ StateIndex SourceState,
        _In_ EventIndex Event,
        _In_ StateIndex TargetState,
        _In_ uint8_t StackDepth);

    static
    IO_WORKITEM_ROUTINE
    WorkerRoutine;

    void
    RunWorker(
        void);

    STATE_MACHINE_ENGINE_CONFIG m_config = {};
    KSPIN_LOCK m_lock;
    KIRQL m_lockIrql = PASSIVE_LEVEL;
    EngineState m_engineState = EngineState::Invalid;
    EventIndex m_eventQueue[EventQueueLength] = {};
    uint8_t m_eventQueueHead = 0;
    uint8_t m_eventQueueTail = 0;
    StateIndex * m_stack = nullptr;
    uint8_t m_stackSize = 0;
    uint8_t m_numStatesOnStack = 0;
    bool m_currentStateAlreadyExited = true;
    bool m_isRunningOnDedicatedThread = true;
    KIRQL m_runningIrql = DISPATCH_LEVEL;
    EVENT_ACTION m_resumeAction = {};
    EventIndex m_timerFiredEvent = 0;
    PIO_WORKITEM m_workItem = nullptr;
    StateMachineEngineImpl ** m_ownerPointer;
    EXCEPTION_RECORD_ENTRY m_exceptionHistory[ExceptionHistoryLength] = {};
    uint8_t m_exceptionHistoryIndex = 0;
    TRANSITION_RECORD_ENTRY m_transitionHistory[TransitionHistoryLength] = {};
    uint8_t m_transitionHistoryIndex = 0;
};

void const *
StateMachineEngine::StateMachineEngineImpl::Slot(
    StateIndex Index,
    StateSlotType Type) const
{
    auto const & state = State(Index);
    auto const active = static_cast<uint16_t>(state.activeSlots);
    auto const type = static_cast<uint16_t>(Type);

    if ((active & type) == 0)
    {
        return nullptr;
    }

    uint32_t position = 0;

    for (uint16_t bit = 1; bit < type; bit <<= 1)
    {
        if (active & bit)
        {
            position++;
        }
    }

    return state.slots[position];
}

NTSTATUS
StateMachineEngine::StateMachineEngineImpl::Initialize(
    STATE_MACHINE_ENGINE_CONFIG const & Config)
{
    m_config = Config;
    m_stackSize = m_config.stackSize != 0 ? m_config.stackSize : DefaultStackSize;

    uint32_t const poolTag = m_config.poolTag != 0 ? m_config.poolTag : DefaultPoolTag;

    m_stack = static_cast<StateIndex *>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, m_stackSize * sizeof(StateIndex), poolTag));

    if (m_stack == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (m_config.isWorkerRequired)
    {
        if (m_config.deviceObject == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        m_workItem = IoAllocateWorkItem(m_config.deviceObject);

        if (m_workItem == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    InitiateFirstRun();
    return STATUS_SUCCESS;
}

void
StateMachineEngine::StateMachineEngineImpl::InitiateFirstRun(
    void)
{
    AcquireLock();
    KIRQL const callerIrql = m_lockIrql;
    m_engineState = EngineState::Running;
    ReleaseLock();

    MarkRunning(callerIrql, false);

    EVENT_ACTION action = {};
    action.action = EventAction::CallTransition;
    action.entry = &m_config.machineSpec->machineTable[m_config.machineSpec->mainMachine];

    EngineState state = ExecuteEventAction(action);

    if (state == EngineState::Running)
    {
        state = ExecuteCurrentState();
    }

    AcquireLock();

    if (state == EngineState::Stopped)
    {
        ProcessEventQueue(false);
    }
    else
    {
        UpdateEngineState(state);
    }
}

void
StateMachineEngine::StateMachineEngineImpl::EnqueueEvent(
    EventIndex Event)
{
    AcquireLock();
    KIRQL const callerIrql = m_lockIrql;

    if (m_engineState == EngineState::WaitingForTimerFiredEvent && Event == m_timerFiredEvent)
    {
        if (m_config.logEventEnqueueCallback != nullptr)
        {
            m_config.logEventEnqueueCallback(m_config.context, m_config.machineSpec->eventTable[Event].id);
        }

        m_timerFiredEvent = 0;
        MarkRunning(callerIrql, false);
        ProcessEventQueue(true);
        return;
    }

    bool const runNow = m_engineState == EngineState::Stopped;

    if (!EnqueueEventWithDisposition(Event))
    {
        return;
    }

    if (!runNow)
    {
        ReleaseLock();
        return;
    }

    MarkRunning(callerIrql, false);
    ProcessEventQueue(false);
}

bool
StateMachineEngine::StateMachineEngineImpl::EnqueueEventWithDisposition(
    EventIndex Event)
{
    auto const disposition = m_config.machineSpec->eventTable[Event].queueingDisposition;

    if (disposition == EventQueueingDisposition::KeepLatestOnly)
    {
        uint8_t write = m_eventQueueHead;
        bool found = false;

        for (uint8_t read = m_eventQueueHead; read != m_eventQueueTail; read = (read + 1) & EventQueueMask)
        {
            if (m_eventQueue[read] == Event)
            {
                found = true;
                continue;
            }

            m_eventQueue[write] = m_eventQueue[read];
            write = (write + 1) & EventQueueMask;
        }

        if (found)
        {
            m_eventQueueTail = write;
        }
    }
    else if (disposition == EventQueueingDisposition::KeepOldestOnly)
    {
        for (uint8_t index = m_eventQueueHead; index != m_eventQueueTail; index = (index + 1) & EventQueueMask)
        {
            if (m_eventQueue[index] == Event)
            {
                ReleaseLock();
                return false;
            }
        }
    }
    else if (disposition != EventQueueingDisposition::Unlimited)
    {
        ReleaseLock();
        return false;
    }

    return AddEventToEventQueue(Event);
}

bool
StateMachineEngine::StateMachineEngineImpl::AddEventToEventQueue(
    EventIndex Event)
{
    uint8_t const nextTail = (m_eventQueueTail + 1) & EventQueueMask;

    if (nextTail == m_eventQueueHead)
    {
        ReportException(MachineException::EventQueueOverflow, Event, 0, true);
        return false;
    }

    m_eventQueue[m_eventQueueTail] = Event;
    m_eventQueueTail = nextTail;

    if (m_config.logEventEnqueueCallback != nullptr)
    {
        m_config.logEventEnqueueCallback(m_config.context, Event != 0 ? m_config.machineSpec->eventTable[Event].id : 0);
    }

    return true;
}

void
StateMachineEngine::StateMachineEngineImpl::FindActionForEvent(
    EventIndex Event,
    EVENT_ACTION & Action) const
{
    Action = {};
    Action.eventIndex = Event;
    Action.action = EventAction::NoAction;
    Action.stackDepth = NoStackDepth;

    for (uint8_t depth = m_numStatesOnStack; depth != 0;)
    {
        depth--;

        StateIndex const stateIndex = m_stack[depth];

        if (auto external = static_cast<EXTERNAL_TRANSITION const *>(Slot(stateIndex, StateSlotType::ExternalTransitions)))
        {
            for (; external->triggeringEventIndex != 0; external++)
            {
                if (external->triggeringEventIndex == Event)
                {
                    Action.action = EventAction::ExternalTransition;
                    Action.entry = external;
                    Action.stackDepth = depth;
                    return;
                }
            }
        }

        if (auto internal = static_cast<INTERNAL_TRANSITION const *>(Slot(stateIndex, StateSlotType::InternalTransitions)))
        {
            for (; internal->triggeringEventIndex != 0; internal++)
            {
                if (internal->triggeringEventIndex == Event)
                {
                    Action.action = EventAction::InternalTransition;
                    Action.entry = internal;
                    Action.stackDepth = depth;
                    return;
                }
            }
        }

        if (auto deferred = static_cast<EventIndex const *>(Slot(stateIndex, StateSlotType::DeferredEvents)))
        {
            for (; *deferred != 0; deferred++)
            {
                if (*deferred == Event)
                {
                    Action.action = EventAction::Defer;
                    Action.stackDepth = depth;
                    return;
                }
            }
        }

        if (auto pop = static_cast<POP_TRANSITION const *>(Slot(stateIndex, StateSlotType::PopTransitions)))
        {
            for (; pop->triggeringEventIndex != 0; pop++)
            {
                if (pop->triggeringEventIndex == Event)
                {
                    Action.action = EventAction::PopTransition;
                    Action.entry = pop;
                    Action.stackDepth = depth;
                    return;
                }
            }
        }

        if (State(stateIndex).type == StateType::Sync)
        {
            return;
        }
    }
}

EngineState
StateMachineEngine::StateMachineEngineImpl::ExitCurrentState(
    EVENT_ACTION const & Action)
{
    if (m_currentStateAlreadyExited)
    {
        return EngineState::Stopped;
    }

    m_currentStateAlreadyExited = true;

    auto details = static_cast<STOP_TIMER_ON_EXIT_DETAILS const *>(
        Slot(CurrentState(), StateSlotType::StopTimerOnExit));

    if (details != nullptr && Action.eventIndex != details->timerFiredEvent &&
        details->stopTimerFunction(m_config.context) != StopTimerResult::TimerStopped)
    {
        SaveResumeAction(Action);
        m_timerFiredEvent = details->timerFiredEvent;
        return EngineState::WaitingForTimerFiredEvent;
    }

    return EngineState::Stopped;
}

EngineState
StateMachineEngine::StateMachineEngineImpl::PopToStackDepth(
    EVENT_ACTION const & Action)
{
    while (static_cast<uint32_t>(Action.stackDepth) + 1 < m_numStatesOnStack)
    {
        EngineState const state = ExitCurrentState(Action);

        if (state != EngineState::Stopped)
        {
            return state;
        }

        StateIndex const below = m_numStatesOnStack >= 2 ? m_stack[m_numStatesOnStack - 2] : 0;
        LogTransition(TransitionType::ImplicitPop, CurrentState(), Action.eventIndex, below, m_numStatesOnStack - 1);

        m_stack[m_numStatesOnStack - 1] = 0;
        m_numStatesOnStack--;
        m_currentStateAlreadyExited = false;
    }

    return EngineState::Stopped;
}

EngineState
StateMachineEngine::StateMachineEngineImpl::ExecuteEventAction(
    EVENT_ACTION & Action)
{
    switch (Action.action)
    {
        case EventAction::NoAction:
        {
            ReportException(MachineException::UnhandledEvent, Action.eventIndex, CurrentState(), false);
            return EngineState::Stopped;
        }

        case EventAction::ExternalTransition:
        {
            EngineState state = PopToStackDepth(Action);

            if (state != EngineState::Stopped)
            {
                return state;
            }

            state = ExitCurrentState(Action);

            if (state != EngineState::Stopped)
            {
                return state;
            }

            auto const transition = static_cast<EXTERNAL_TRANSITION const *>(Action.entry);
            StateIndex const target = transition->targetStateIndex;
            auto const flags = State(target).flags;

            if (!CanRunOnCurrentContext(WI_IsFlagSet(flags, StateFlags::RequiresPassiveLevel),
                                        WI_IsFlagSet(flags, StateFlags::RequiresDedicatedThread)))
            {
                SaveResumeAction(Action);
                return EngineState::WaitingForWorkerStateEntry;
            }

            LogTransition(TransitionType::External, CurrentState(), Action.eventIndex, target, Action.stackDepth);
            m_stack[m_numStatesOnStack - 1] = target;
            m_currentStateAlreadyExited = false;
            return EngineState::Running;
        }

        case EventAction::InternalTransition:
        {
            auto const transition = static_cast<INTERNAL_TRANSITION const *>(Action.entry);

            if (transition->action == nullptr)
            {
                LogTransition(TransitionType::Ignore, CurrentState(), Action.eventIndex, m_stack[Action.stackDepth], Action.stackDepth);
                return EngineState::Stopped;
            }

            if (!CanRunOnCurrentContext(WI_IsFlagSet(transition->flags, InternalTransitionFlags::RequiresPassiveLevel),
                                        WI_IsFlagSet(transition->flags, InternalTransitionFlags::RequiresDedicatedThread)))
            {
                SaveResumeAction(Action);
                return EngineState::WaitingForWorkerEventAction;
            }

            LogTransition(TransitionType::Internal, CurrentState(), Action.eventIndex, m_stack[Action.stackDepth], Action.stackDepth);
            transition->action(m_config.context);
            return EngineState::Stopped;
        }

        case EventAction::PopTransition:
        {
            EVENT_ACTION current = Action;

            for (;;)
            {
                EngineState state = PopToStackDepth(current);

                if (state != EngineState::Stopped)
                {
                    return state;
                }

                state = ExitCurrentState(current);

                if (state != EngineState::Stopped)
                {
                    return state;
                }

                StateIndex const below = m_numStatesOnStack >= 2 ? m_stack[m_numStatesOnStack - 2] : 0;
                LogTransition(TransitionType::ExplicitPop, CurrentState(), current.eventIndex, below, current.stackDepth);

                m_stack[m_numStatesOnStack - 1] = 0;
                m_numStatesOnStack--;
                m_currentStateAlreadyExited = false;

                auto const pop = static_cast<POP_TRANSITION const *>(current.entry);
                FindActionForEvent(pop->returnEventIndex, current);

                if (current.action == EventAction::PopTransition)
                {
                    continue;
                }

                if (m_numStatesOnStack == 0)
                {
                    return EngineState::Stopped;
                }

                if (current.action == EventAction::Defer)
                {
                    current.action = EventAction::NoAction;
                }

                return ExecuteEventAction(current);
            }
        }

        case EventAction::CallTransition:
        {
            if (m_numStatesOnStack == m_stackSize)
            {
                ReportException(MachineException::StackOverflow, 0, CurrentState(), false);
                return EngineState::Stopped;
            }

            auto const submachine = static_cast<SUBMACHINE_SPECIFICATION const *>(Action.entry);
            StateIndex const target = submachine->initialStateIndex;
            auto const flags = State(target).flags;

            if (!CanRunOnCurrentContext(WI_IsFlagSet(flags, StateFlags::RequiresPassiveLevel),
                                        WI_IsFlagSet(flags, StateFlags::RequiresDedicatedThread)))
            {
                SaveResumeAction(Action);
                return EngineState::WaitingForWorkerStateEntry;
            }

            LogTransition(TransitionType::Call, CurrentState(), 0, target, m_numStatesOnStack);
            m_stack[m_numStatesOnStack] = target;
            m_numStatesOnStack++;
            m_currentStateAlreadyExited = false;
            return EngineState::Running;
        }

        default:
            return EngineState::Stopped;
    }
}

EngineState
StateMachineEngine::StateMachineEngineImpl::ExecuteCurrentState(
    void)
{
    for (;;)
    {
        StateIndex const stateIndex = CurrentState();
        auto const & state = State(stateIndex);
        EventIndex returnEvent = 0;

        if (auto entry = reinterpret_cast<StateEntryFunction *>(
                const_cast<void *>(Slot(stateIndex, StateSlotType::EntryFunction))))
        {
            returnEvent = entry(m_config.context);
        }
        else if (state.type == StateType::Sync)
        {
            returnEvent = m_config.machineSpec->defaultSyncEvent;
        }

        if (auto purge = static_cast<EventIndex const *>(Slot(stateIndex, StateSlotType::PurgeEvents)))
        {
            AcquireLock();

            uint8_t write = m_eventQueueHead;

            for (uint8_t read = m_eventQueueHead; read != m_eventQueueTail; read = (read + 1) & EventQueueMask)
            {
                EventIndex const queued = m_eventQueue[read];
                bool purged = false;

                for (EventIndex const * candidate = purge; *candidate != 0; candidate++)
                {
                    if (*candidate == queued)
                    {
                        purged = true;
                        break;
                    }
                }

                if (purged)
                {
                    LogTransition(TransitionType::Purge, stateIndex, queued, 0, m_numStatesOnStack - 1);
                    continue;
                }

                m_eventQueue[write] = queued;
                write = (write + 1) & EventQueueMask;
            }

            m_eventQueueTail = write;
            ReleaseLock();
        }

        EVENT_ACTION action = {};

        if (state.type == StateType::Sync)
        {
            FindActionForEvent(returnEvent, action);
        }
        else if (state.type == StateType::Call)
        {
            action.action = EventAction::CallTransition;
            action.entry = &m_config.machineSpec->machineTable[state.callSubmachine];
        }
        else
        {
            return EngineState::Stopped;
        }

        EngineState const result = ExecuteEventAction(action);

        if (result != EngineState::Running)
        {
            return result;
        }
    }
}

void
StateMachineEngine::StateMachineEngineImpl::ProcessEventQueue(
    bool ResumeAfterTimer)
{
    bool resume = ResumeAfterTimer;
    m_engineState = EngineState::Running;

    for (;;)
    {
        EVENT_ACTION action = {};

        if (resume)
        {
            action = m_resumeAction;
            resume = false;
        }
        else
        {
            uint8_t index = m_eventQueueHead;
            bool found = false;

            for (; index != m_eventQueueTail; index = (index + 1) & EventQueueMask)
            {
                FindActionForEvent(m_eventQueue[index], action);

                if (action.action != EventAction::Defer)
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                UpdateEngineState(EngineState::Stopped);
                return;
            }

            while (index != m_eventQueueHead)
            {
                uint8_t const previous = (index - 1) & EventQueueMask;
                m_eventQueue[index] = m_eventQueue[previous];
                index = previous;
            }

            m_eventQueueHead = (m_eventQueueHead + 1) & EventQueueMask;

            if (action.eventIndex == 0)
            {
                UpdateEngineState(EngineState::Stopped);
                return;
            }
        }

        ReleaseLock();

        EngineState state = ExecuteEventAction(action);

        if (state == EngineState::Running)
        {
            state = ExecuteCurrentState();
        }

        AcquireLock();

        if (state == EngineState::Stopped || state == EngineState::Running)
        {
            continue;
        }

        if (state != EngineState::WaitingForTimerFiredEvent)
        {
            UpdateEngineState(state);
            return;
        }

        bool timerFired = false;
        uint8_t write = m_eventQueueHead;

        for (uint8_t read = m_eventQueueHead; read != m_eventQueueTail; read = (read + 1) & EventQueueMask)
        {
            if (!timerFired && m_eventQueue[read] == m_timerFiredEvent)
            {
                timerFired = true;
                continue;
            }

            m_eventQueue[write] = m_eventQueue[read];
            write = (write + 1) & EventQueueMask;
        }

        m_eventQueueTail = write;

        if (!timerFired)
        {
            UpdateEngineState(EngineState::WaitingForTimerFiredEvent);
            return;
        }

        m_timerFiredEvent = 0;
        resume = true;
    }
}

void
StateMachineEngine::StateMachineEngineImpl::UpdateEngineState(
    EngineState NewState)
{
    m_engineState = NewState;

    if (NewState == EngineState::WaitingForWorkerStateEntry ||
        NewState == EngineState::WaitingForWorkerEventAction)
    {
        ReleaseLock();
        NT_FRE_ASSERT(m_workItem != nullptr);
        IoQueueWorkItem(m_workItem, WorkerRoutine, DelayedWorkQueue, this);
        return;
    }

    if (NewState == EngineState::WaitingForTimerFiredEvent)
    {
        ReleaseLock();
        return;
    }

    StateIndex const top = CurrentState();
    ReleaseLock();

    if (top == 0)
    {
        Destroy(true);
    }
}

void
StateMachineEngine::StateMachineEngineImpl::WorkerRoutine(
    PDEVICE_OBJECT DeviceObject,
    PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    static_cast<StateMachineEngineImpl *>(Context)->RunWorker();
}

void
StateMachineEngine::StateMachineEngineImpl::RunWorker(
    void)
{
    AcquireLock();
    EngineState const pending = m_engineState;
    m_engineState = EngineState::Running;
    ReleaseLock();

    MarkRunning(PASSIVE_LEVEL, true);

    EngineState state = EngineState::Stopped;

    if (pending == EngineState::WaitingForWorkerStateEntry)
    {
        state = ExecuteEventAction(m_resumeAction);

        if (state == EngineState::Running)
        {
            state = ExecuteCurrentState();
        }
    }
    else if (pending == EngineState::WaitingForWorkerEventAction)
    {
        state = ExecuteEventAction(m_resumeAction);
        m_resumeAction = {};
    }
    else
    {
        return;
    }

    AcquireLock();

    if (state == EngineState::Stopped || state == EngineState::Running)
    {
        ProcessEventQueue(false);
        return;
    }

    if (state == EngineState::WaitingForTimerFiredEvent)
    {
        for (uint8_t index = m_eventQueueHead; index != m_eventQueueTail; index = (index + 1) & EventQueueMask)
        {
            if (m_eventQueue[index] == m_timerFiredEvent)
            {
                uint8_t write = index;

                for (uint8_t read = (index + 1) & EventQueueMask; read != m_eventQueueTail; read = (read + 1) & EventQueueMask)
                {
                    m_eventQueue[write] = m_eventQueue[read];
                    write = (write + 1) & EventQueueMask;
                }

                m_eventQueueTail = write;
                m_timerFiredEvent = 0;
                ProcessEventQueue(true);
                return;
            }
        }
    }

    UpdateEngineState(state);
}

void
StateMachineEngine::StateMachineEngineImpl::ReportException(
    MachineException Exception,
    EventIndex Event,
    StateIndex State,
    bool LockHeld)
{
    if (!LockHeld)
    {
        AcquireLock();
    }

    m_exceptionHistory[m_exceptionHistoryIndex] = { Exception, Event, State };
    m_exceptionHistoryIndex = (m_exceptionHistoryIndex + 1) & (ExceptionHistoryLength - 1);

    ReleaseLock();

    if (m_config.logExceptionCallback != nullptr)
    {
        m_config.logExceptionCallback(
            m_config.context,
            Exception,
            Event != 0 ? m_config.machineSpec->eventTable[Event].id : 0,
            State != 0 ? m_config.machineSpec->stateTable[State].id : 0);
    }
}

void
StateMachineEngine::StateMachineEngineImpl::LogTransition(
    TransitionType Type,
    StateIndex SourceState,
    EventIndex Event,
    StateIndex TargetState,
    uint8_t StackDepth)
{
    auto & record = m_transitionHistory[m_transitionHistoryIndex];
    record.transitionType = Type;
    record.processedEvent = Event;
    record.stateIndex = (Type == TransitionType::Internal || Type == TransitionType::Ignore) ? TargetState : SourceState;
    record.stackDepth = StackDepth;
    m_transitionHistoryIndex = (m_transitionHistoryIndex + 1) & (TransitionHistoryLength - 1);

    if (m_config.logTransitionCallback != nullptr)
    {
        m_config.logTransitionCallback(
            m_config.context,
            Type,
            SourceState != 0 ? m_config.machineSpec->stateTable[SourceState].id : 0,
            Event != 0 ? m_config.machineSpec->eventTable[Event].id : 0,
            TargetState != 0 ? m_config.machineSpec->stateTable[TargetState].id : 0);
    }
}

void
StateMachineEngine::StateMachineEngineImpl::Destroy(
    bool NotifyOwner)
{
    auto const callback = m_config.machineDestroyedCallback;
    auto const context = m_config.context;

    *m_ownerPointer = nullptr;

    AcquireLock();
    m_engineState = EngineState::Invalid;
    ReleaseLock();

    if (m_workItem != nullptr)
    {
        IoFreeWorkItem(m_workItem);
        m_workItem = nullptr;
    }

    if (m_stack != nullptr)
    {
        ExFreePool(m_stack);
        m_stack = nullptr;
    }

    this->~StateMachineEngineImpl();
    ExFreePool(this);

    if (NotifyOwner && callback != nullptr)
    {
        callback(context);
    }
}

StateMachineEngine::~StateMachineEngine()
{
    if (m_impl != nullptr)
    {
        m_impl->Destroy(false);
    }
}

NTSTATUS
StateMachineEngine::Initialize(
    STATE_MACHINE_ENGINE_CONFIG const & config)
{
    uint32_t const poolTag = config.poolTag != 0 ? config.poolTag : DefaultPoolTag;
    void * memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(StateMachineEngineImpl), poolTag);

    if (memory == nullptr)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    m_impl = new (memory) StateMachineEngineImpl(&m_impl);

    NTSTATUS const status = m_impl->Initialize(config);

    if (!NT_SUCCESS(status) && m_impl != nullptr)
    {
        m_impl->Destroy(false);
    }

    return status;
}

bool
StateMachineEngine::IsInitialized() const
{
    return m_impl != nullptr;
}

void
StateMachineEngine::EnqueueEvent(
    EventIndex eventIndex)
{
    NT_ASSERT(m_impl != nullptr);
    m_impl->EnqueueEvent(eventIndex);
}

}
