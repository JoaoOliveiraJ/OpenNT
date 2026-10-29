/*
 * PROJECT:     OpenNT Linux Subsystem
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Kernel log buffer: /dev/kmsg, syslog(2) and the printk sysctls
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#include "lxcore.h"

#define NDEBUG
#include <debug.h>

#define LX_KLOG_MAX_RECORDS     4096
#define LX_KLOG_BUFFER_SIZE     262144
#define LX_KLOG_LINE_MAX        1024
#define LX_KLOG_FACILITY_KERN   0
#define LX_KLOG_FACILITY_USER   1

#define LX_SYSLOG_ACTION_CLOSE          0
#define LX_SYSLOG_ACTION_OPEN           1
#define LX_SYSLOG_ACTION_READ           2
#define LX_SYSLOG_ACTION_READ_ALL       3
#define LX_SYSLOG_ACTION_READ_CLEAR     4
#define LX_SYSLOG_ACTION_CLEAR          5
#define LX_SYSLOG_ACTION_CONSOLE_OFF    6
#define LX_SYSLOG_ACTION_CONSOLE_ON     7
#define LX_SYSLOG_ACTION_CONSOLE_LEVEL  8
#define LX_SYSLOG_ACTION_SIZE_UNREAD    9
#define LX_SYSLOG_ACTION_SIZE_BUFFER    10

#define LX_DEVKMSG_ON           0
#define LX_DEVKMSG_OFF          1
#define LX_DEVKMSG_RATELIMIT    2

typedef struct _LX_KLOG_RECORD
{
    ULONG64 Seq;
    ULONG64 TimeUsec;
    UCHAR Facility;
    UCHAR Level;
    USHORT Length;
    CHAR Text[ANYSIZE_ARRAY];
} LX_KLOG_RECORD, *PLX_KLOG_RECORD;

typedef struct _LX_KMSG_USER
{
    ULONG64 Seq;
    LX_RATELIMIT Limit;
} LX_KMSG_USER, *PLX_KMSG_USER;

static FAST_MUTEX LxKlogLock;
static PLX_KLOG_RECORD LxKlogRecords[LX_KLOG_MAX_RECORDS];
static ULONG64 LxKlogFirstSeq;
static ULONG64 LxKlogNextSeq;
static ULONG64 LxKlogClearSeq;
static ULONG64 LxKlogSyslogSeq;
static ULONG LxKlogBytes;
static LX_POLL_HEAD LxKlogPoll;
static LONG LxKlogConsoleLevel = 4;
static LONG LxKlogDefaultMessageLevel = 4;
static LONG LxKlogMinimumConsoleLevel = 1;
static LONG LxKlogDefaultConsoleLevel = 7;
static LONG LxKlogSavedConsoleLevel = -1;
static LONG LxKlogDmesgRestrict = 1;
static LONG LxKlogDevkmsgMode = LX_DEVKMSG_ON;
LONG LxPrintkRatelimitSeconds = 5;
LONG LxPrintkRatelimitBurst = 10;

BOOLEAN
LxRatelimit(
    _Inout_ PLX_RATELIMIT Limit,
    _In_ LONG IntervalSeconds,
    _In_ LONG Burst,
    _Out_opt_ PLONG Missed)
{
    LONG64 Now = (LONG64)KeQueryInterruptTime();
    BOOLEAN Allowed;

    if (Missed != NULL)
        *Missed = 0;
    if (IntervalSeconds <= 0)
        return TRUE;
    ExAcquireFastMutex(&LxKlogLock);
    if (Limit->Begin == 0)
        Limit->Begin = Now;
    if (Now - Limit->Begin > (LONG64)IntervalSeconds * 10000000LL)
    {
        Limit->Begin = Now;
        Limit->Printed = 0;
        if (Missed != NULL)
        {
            *Missed = Limit->Missed;
            Limit->Missed = 0;
        }
    }
    if ((Burst > 0) && (Limit->Printed < Burst))
    {
        Limit->Printed++;
        Allowed = TRUE;
    }
    else
    {
        Limit->Missed++;
        Allowed = FALSE;
    }
    ExReleaseFastMutex(&LxKlogLock);
    return Allowed;
}

static
VOID
LxKlogDropOldestLocked(VOID)
{
    PLX_KLOG_RECORD Old = LxKlogRecords[LxKlogFirstSeq % LX_KLOG_MAX_RECORDS];

    LxKlogRecords[LxKlogFirstSeq % LX_KLOG_MAX_RECORDS] = NULL;
    if (Old != NULL)
    {
        LxKlogBytes -= Old->Length;
        LxFree(Old);
    }
    LxKlogFirstSeq++;
    if (LxKlogClearSeq < LxKlogFirstSeq)
        LxKlogClearSeq = LxKlogFirstSeq;
    if (LxKlogSyslogSeq < LxKlogFirstSeq)
        LxKlogSyslogSeq = LxKlogFirstSeq;
}

static
VOID
LxKlogEcho(
    _In_z_ PCSTR Line,
    _In_ UCHAR Level)
{
    PLIST_ENTRY Entry;

    DbgPrint("%s", Line);
    if (Level >= (UCHAR)LxKlogConsoleLevel)
        return;
    ExAcquireFastMutex(&LxInstanceListLock);
    for (Entry = LxInstanceList.Flink; Entry != &LxInstanceList; Entry = Entry->Flink)
    {
        PLX_INSTANCE Instance = CONTAINING_RECORD(Entry, LX_INSTANCE, Link);

        if (Instance->Console != NULL)
            LxTtyKernelWrite(Instance->Console, Line, (ULONG)strlen(Line));
    }
    ExReleaseFastMutex(&LxInstanceListLock);
}

static
VOID
LxKlogAppend(
    _In_ UCHAR Facility,
    _In_ UCHAR Level,
    _In_reads_(Length) PCSTR Text,
    _In_ ULONG Length)
{
    CHAR Line[LX_KLOG_LINE_MAX + 32];
    PLX_KLOG_RECORD Record;
    NTSTATUS Status;

    if (Length > LX_KLOG_LINE_MAX - 1)
        Length = LX_KLOG_LINE_MAX - 1;
    Record = LxAlloc(FIELD_OFFSET(LX_KLOG_RECORD, Text) + Length + 1);
    if (Record == NULL)
        return;
    Record->TimeUsec = (ULONG64)KeQueryInterruptTime() / 10;
    Record->Facility = Facility;
    Record->Level = Level;
    Record->Length = (USHORT)Length;
    RtlCopyMemory(Record->Text, Text, Length);
    Status = RtlStringCbPrintfA(Line, sizeof(Line), "[%5llu.%06llu] %.*s\n", Record->TimeUsec / 1000000,
                                Record->TimeUsec % 1000000, (int)Length, Record->Text);
    if (!NT_SUCCESS(Status) && (Status != STATUS_BUFFER_OVERFLOW))
        Line[0] = '\0';

    ExAcquireFastMutex(&LxKlogLock);
    while ((LxKlogNextSeq - LxKlogFirstSeq >= LX_KLOG_MAX_RECORDS) ||
           ((LxKlogFirstSeq < LxKlogNextSeq) && (LxKlogBytes + Length > LX_KLOG_BUFFER_SIZE)))
    {
        LxKlogDropOldestLocked();
    }
    Record->Seq = LxKlogNextSeq++;
    LxKlogRecords[Record->Seq % LX_KLOG_MAX_RECORDS] = Record;
    LxKlogBytes += Length;
    ExReleaseFastMutex(&LxKlogLock);
    if (Line[0] != '\0')
        LxKlogEcho(Line, Level);
    LxPollWake(&LxKlogPoll, LX_POLLIN | LX_POLLRDNORM);
}

VOID
LxKlogWrite(
    _In_ ULONG Priority,
    _In_reads_(Length) PCSTR Text,
    _In_ ULONG Length)
{
    if (Length > LX_KLOG_LINE_MAX - 1)
        Length = LX_KLOG_LINE_MAX - 1;
    if ((Length != 0) && (Text[Length - 1] == '\n'))
        Length--;
    LxKlogAppend((UCHAR)(Priority >> 3), (UCHAR)(Priority & 7), Text, Length);
}

VOID
LxKlogPrintf(
    _In_ ULONG Priority,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...)
{
    CHAR Line[LX_KLOG_LINE_MAX];
    va_list Arguments;
    NTSTATUS Status;

    va_start(Arguments, Format);
    Status = RtlStringCbVPrintfA(Line, sizeof(Line), Format, Arguments);
    va_end(Arguments);
    if (!NT_SUCCESS(Status) && (Status != STATUS_BUFFER_OVERFLOW))
        return;
    LxKlogWrite(Priority, Line, (ULONG)strlen(Line));
}

VOID
LxKlogInitialize(VOID)
{
    ExInitializeFastMutex(&LxKlogLock);
    LxPollHeadInit(&LxKlogPoll);
    LxKlogPrintf(LX_KLOG_FACILITY_KERN << 3 | 5, "%s", LX_KERNEL_VERSION);
}

static
BOOLEAN
LxKlogReadAllowed(
    _In_ PLX_PROCESS Process)
{
    return !LxKlogDmesgRestrict || LxCapable(Process, LX_CAP_SYSLOG) || LxCapable(Process, LX_CAP_SYS_ADMIN);
}

static
ULONG
LxKlogFormatKmsg(
    _In_ PLX_KLOG_RECORD Record,
    _Out_writes_(Size) PSTR Buffer,
    _In_ ULONG Size)
{
    ULONG Used, Index;

    if (!NT_SUCCESS(RtlStringCbPrintfA(Buffer, Size, "%u,%llu,%llu,-;", (ULONG)(Record->Facility << 3 | Record->Level),
                                       Record->Seq, Record->TimeUsec)))
    {
        return 0;
    }
    Used = (ULONG)strlen(Buffer);
    for (Index = 0; Index < Record->Length; Index++)
    {
        UCHAR Byte = (UCHAR)Record->Text[Index];

        if ((Byte < ' ') || (Byte >= 127) || (Byte == '\\'))
        {
            if (Used + 4 >= Size)
                return 0;
            RtlStringCbPrintfA(Buffer + Used, Size - Used, "\\x%02x", Byte);
            Used += 4;
        }
        else
        {
            if (Used + 1 >= Size)
                return 0;
            Buffer[Used++] = (CHAR)Byte;
        }
    }
    if (Used + 1 >= Size)
        return 0;
    Buffer[Used++] = '\n';
    Buffer[Used] = '\0';
    return Used;
}

static
ULONG
LxKlogFormatSyslog(
    _In_ PLX_KLOG_RECORD Record,
    _Out_writes_(Size) PSTR Buffer,
    _In_ ULONG Size)
{
    NTSTATUS Status = RtlStringCbPrintfA(Buffer, Size, "<%u>[%5llu.%06llu] %.*s\n",
                                         (ULONG)(Record->Facility << 3 | Record->Level), Record->TimeUsec / 1000000,
                                         Record->TimeUsec % 1000000, (int)Record->Length, Record->Text);

    return NT_SUCCESS(Status) ? (ULONG)strlen(Buffer) : 0;
}

static
BOOLEAN
LxKmsgReady(
    _In_ PVOID Context)
{
    PLX_KMSG_USER User = Context;

    return User->Seq < *(volatile ULONG64 *)&LxKlogNextSeq;
}

static
LONG64
LxKmsgRead(
    _In_ PLX_FILE File,
    _In_ ULONG64 Buffer,
    _In_ ULONG64 Length,
    _Inout_opt_ PLONG64 Offset)
{
    PLX_KMSG_USER User = File->Object;
    CHAR Line[LX_KLOG_LINE_MAX * 4 + 64];
    PLX_KLOG_RECORD Record;
    ULONG Count;
    LONG64 Result;

    UNREFERENCED_PARAMETER(Offset);
    for (;;)
    {
        ExAcquireFastMutex(&LxKlogLock);
        if (User->Seq < LxKlogFirstSeq)
        {
            User->Seq = LxKlogFirstSeq;
            ExReleaseFastMutex(&LxKlogLock);
            return -LX_EPIPE;
        }
        if (User->Seq < LxKlogNextSeq)
            break;
        ExReleaseFastMutex(&LxKlogLock);
        if (File->Flags & LX_O_NONBLOCK)
            return -LX_EAGAIN;
        Result = LxWaitHead(&LxKlogPoll, LxKmsgReady, User, NULL);
        if (Result != 0)
            return (Result == -LX_EINTR) ? -LX_ERESTARTSYS : Result;
    }
    Record = LxKlogRecords[User->Seq % LX_KLOG_MAX_RECORDS];
    Count = LxKlogFormatKmsg(Record, Line, sizeof(Line));
    User->Seq++;
    if ((Count == 0) || (Count > Length))
    {
        ExReleaseFastMutex(&LxKlogLock);
        return -LX_EINVAL;
    }
    ExReleaseFastMutex(&LxKlogLock);
    Result = LxCopyToUser(Buffer, Line, Count);
    return (Result != 0) ? Result : (LONG64)Count;
}

static
LONG64
LxKmsgWriteVector(
    _In_ PLX_FILE File,
    _In_reads_(Count) PLX_IOVEC Vectors,
    _In_ ULONG Count,
    _Inout_opt_ PLONG64 Offset)
{
    PLX_KMSG_USER User = File->Object;
    CHAR Data[LX_KLOG_LINE_MAX + 1];
    ULONG Facility = LX_KLOG_FACILITY_USER, Level = (ULONG)LxKlogDefaultMessageLevel, Start = 0, Used = 0, Index;
    ULONG64 Length = 0;
    LONG64 Result;

    UNREFERENCED_PARAMETER(Offset);
    for (Index = 0; Index < Count; Index++)
    {
        if (Vectors[Index].Length > LX_KLOG_LINE_MAX)
            return -LX_EINVAL;
        Length += Vectors[Index].Length;
    }
    if (Length > LX_KLOG_LINE_MAX)
        return -LX_EINVAL;
    if (LxKlogDevkmsgMode == LX_DEVKMSG_OFF)
        return (LONG64)Length;
    if ((LxKlogDevkmsgMode != LX_DEVKMSG_ON) && !LxRatelimit(&User->Limit, 5, 10, NULL))
        return (LONG64)Length;
    for (Index = 0; Index < Count; Index++)
    {
        Result = LxCopyFromUser(Data + Used, Vectors[Index].Base, Vectors[Index].Length);
        if (Result != 0)
            return Result;
        Used += (ULONG)Vectors[Index].Length;
    }
    Data[Used] = '\0';
    if (Data[0] == '<')
    {
        ULONG Value = 0, Cursor = 1;

        while ((Data[Cursor] >= '0') && (Data[Cursor] <= '9'))
            Value = Value * 10 + (Data[Cursor++] - '0');
        if (Data[Cursor] == '>')
        {
            if ((Value >> 3) != 0)
                Facility = Value >> 3;
            Level = Value & 7;
            Start = Cursor + 1;
        }
    }
    LxKlogWrite(Facility << 3 | Level, Data + Start, (ULONG)strlen(Data + Start));
    return (LONG64)Length;
}

static
LONG64
LxKmsgWrite(
    _In_ PLX_FILE File,
    _In_ ULONG64 Buffer,
    _In_ ULONG64 Length,
    _Inout_opt_ PLONG64 Offset)
{
    LX_IOVEC Vector;

    Vector.Base = Buffer;
    Vector.Length = Length;
    return LxKmsgWriteVector(File, &Vector, 1, Offset);
}

static
ULONG
LxKmsgPoll(
    _In_ PLX_FILE File,
    _In_opt_ PLX_POLL_ENTRY Entry)
{
    PLX_KMSG_USER User = File->Object;
    ULONG Mask = 0;

    if (Entry != NULL)
        LxPollAdd(&LxKlogPoll, Entry);
    ExAcquireFastMutex(&LxKlogLock);
    if ((File->Flags & LX_O_ACCMODE) == LX_O_WRONLY)
        Mask = 0;
    else if (User->Seq < LxKlogFirstSeq)
        Mask = LX_POLLIN | LX_POLLRDNORM | LX_POLLERR | LX_POLLPRI;
    else if (User->Seq < LxKlogNextSeq)
        Mask = LX_POLLIN | LX_POLLRDNORM;
    ExReleaseFastMutex(&LxKlogLock);
    return Mask | LX_POLLOUT | LX_POLLWRNORM;
}

static
LONG64
LxKmsgSeek(
    _In_ PLX_FILE File,
    _In_ LONG64 Offset,
    _In_ ULONG Whence)
{
    PLX_KMSG_USER User = File->Object;

    if (Offset != 0)
        return -LX_ESPIPE;
    ExAcquireFastMutex(&LxKlogLock);
    switch (Whence)
    {
        case LX_SEEK_SET:
            User->Seq = LxKlogFirstSeq;
            break;
        case LX_SEEK_DATA:
            User->Seq = LxKlogClearSeq;
            break;
        case LX_SEEK_END:
            User->Seq = LxKlogNextSeq;
            break;
        default:
            ExReleaseFastMutex(&LxKlogLock);
            return -LX_EINVAL;
    }
    ExReleaseFastMutex(&LxKlogLock);
    return 0;
}

static
VOID
LxKmsgRelease(
    _In_ PLX_FILE File)
{
    PLX_KMSG_USER User = File->Object;
    PLX_THREAD Thread = LxCurrentThread();

    if (User->Limit.Missed != 0)
    {
        LxKlogPrintf(LX_KLOG_FACILITY_KERN << 3 | 4, "%s: %ld output lines suppressed due to ratelimiting",
                     (Thread != NULL) ? Thread->Process->Comm : "", User->Limit.Missed);
    }
    LxFree(User);
}

static const LX_FILE_OPS LxKmsgOps =
{
    LxKmsgRead, LxKmsgWrite, NULL, LxKmsgPoll, LxDeviceStat, LxKmsgSeek, NULL, NULL, LxKmsgRelease, LxKmsgWriteVector
};

LONG
LxKmsgOpen(
    _In_ PLX_PROCESS Process,
    _In_ ULONG Flags,
    _Out_ PLX_FILE *Result)
{
    PLX_KMSG_USER User;
    PLX_FILE File;

    *Result = NULL;
    if (LxKlogDevkmsgMode == LX_DEVKMSG_OFF)
        return -LX_EPERM;
    if (((Flags & LX_O_ACCMODE) != LX_O_WRONLY) && !LxKlogReadAllowed(Process))
        return -LX_EPERM;
    User = LxAlloc(sizeof(*User));
    if (User == NULL)
        return -LX_ENOMEM;
    File = LxFileAlloc(&LxKmsgOps, Flags & (LX_O_ACCMODE | LX_O_NONBLOCK), LX_S_IFCHR);
    if (File == NULL)
    {
        LxFree(User);
        return -LX_ENOMEM;
    }
    ExAcquireFastMutex(&LxKlogLock);
    User->Seq = LxKlogFirstSeq;
    ExReleaseFastMutex(&LxKlogLock);
    File->Object = User;
    *Result = File;
    return 0;
}

static
LONG64
LxSyslogRead(
    _In_ ULONG64 Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN Clear,
    _In_ BOOLEAN Consume)
{
    CHAR Line[LX_KLOG_LINE_MAX + 64];
    ULONG64 Seq, Start;
    ULONG Total = 0, Count, Need = 0, Size = min(Length, LX_KLOG_BUFFER_SIZE * 2);
    PCHAR Text = LxAlloc(Size);
    LONG64 Error;

    if (Text == NULL)
        return -LX_ENOMEM;
    ExAcquireFastMutex(&LxKlogLock);
    if (Consume)
    {
        Start = LxKlogSyslogSeq;
    }
    else
    {
        Start = LxKlogNextSeq;
        for (Seq = LxKlogNextSeq; Seq > LxKlogClearSeq; Seq--)
        {
            Count = LxKlogFormatSyslog(LxKlogRecords[(Seq - 1) % LX_KLOG_MAX_RECORDS], Line, sizeof(Line));
            if (Need + Count > Size)
                break;
            Need += Count;
            Start = Seq - 1;
        }
    }
    for (Seq = Start; Seq < LxKlogNextSeq; Seq++)
    {
        Count = LxKlogFormatSyslog(LxKlogRecords[Seq % LX_KLOG_MAX_RECORDS], Line, sizeof(Line));
        if (Total + Count > Size)
            break;
        RtlCopyMemory(Text + Total, Line, Count);
        Total += Count;
    }
    if (Consume)
        LxKlogSyslogSeq = Seq;
    if (Clear)
        LxKlogClearSeq = LxKlogNextSeq;
    ExReleaseFastMutex(&LxKlogLock);
    Error = (Total != 0) ? LxCopyToUser(Buffer, Text, Total) : 0;
    LxFree(Text);
    return (Error != 0) ? Error : (LONG64)Total;
}

static
BOOLEAN
LxSyslogReady(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    return *(volatile ULONG64 *)&LxKlogSyslogSeq < *(volatile ULONG64 *)&LxKlogNextSeq;
}

LX_SYSCALL(LxSysSyslog)
{
    ULONG Action = (ULONG)Call->Args[0];
    ULONG64 Buffer = Call->Args[1];
    LONG Length = (LONG)Call->Args[2];
    CHAR Line[LX_KLOG_LINE_MAX + 64];
    ULONG64 Seq;
    LONG64 Result = 0;

    if ((LxKlogDmesgRestrict || ((Action != LX_SYSLOG_ACTION_READ_ALL) && (Action != LX_SYSLOG_ACTION_SIZE_BUFFER))) &&
        !LxCapable(Call->Process, LX_CAP_SYSLOG) && !LxCapable(Call->Process, LX_CAP_SYS_ADMIN))
    {
        return -LX_EPERM;
    }
    if (Action > LX_SYSLOG_ACTION_SIZE_BUFFER)
        return -LX_EINVAL;

    switch (Action)
    {
        case LX_SYSLOG_ACTION_CLOSE:
        case LX_SYSLOG_ACTION_OPEN:
            return 0;

        case LX_SYSLOG_ACTION_READ:
            if ((Buffer == 0) || (Length < 0))
                return -LX_EINVAL;
            if (Length == 0)
                return 0;
            Result = LxWaitHead(&LxKlogPoll, LxSyslogReady, NULL, NULL);
            if (Result != 0)
                return (Result == -LX_EINTR) ? -LX_ERESTARTSYS : Result;
            return LxSyslogRead(Buffer, (ULONG)Length, FALSE, TRUE);

        case LX_SYSLOG_ACTION_READ_ALL:
        case LX_SYSLOG_ACTION_READ_CLEAR:
            if ((Buffer == 0) || (Length < 0))
                return -LX_EINVAL;
            if (Length == 0)
                return 0;
            return LxSyslogRead(Buffer, (ULONG)Length, Action == LX_SYSLOG_ACTION_READ_CLEAR, FALSE);

        case LX_SYSLOG_ACTION_CLEAR:
            ExAcquireFastMutex(&LxKlogLock);
            LxKlogClearSeq = LxKlogNextSeq;
            ExReleaseFastMutex(&LxKlogLock);
            return 0;

        case LX_SYSLOG_ACTION_CONSOLE_OFF:
            ExAcquireFastMutex(&LxKlogLock);
            if (LxKlogSavedConsoleLevel == -1)
                LxKlogSavedConsoleLevel = LxKlogConsoleLevel;
            LxKlogConsoleLevel = LxKlogMinimumConsoleLevel;
            ExReleaseFastMutex(&LxKlogLock);
            return 0;

        case LX_SYSLOG_ACTION_CONSOLE_ON:
            ExAcquireFastMutex(&LxKlogLock);
            if (LxKlogSavedConsoleLevel != -1)
            {
                LxKlogConsoleLevel = LxKlogSavedConsoleLevel;
                LxKlogSavedConsoleLevel = -1;
            }
            ExReleaseFastMutex(&LxKlogLock);
            return 0;

        case LX_SYSLOG_ACTION_CONSOLE_LEVEL:
            if ((Length < 1) || (Length > 8))
                return -LX_EINVAL;
            ExAcquireFastMutex(&LxKlogLock);
            LxKlogConsoleLevel = max(Length, LxKlogMinimumConsoleLevel);
            LxKlogSavedConsoleLevel = -1;
            ExReleaseFastMutex(&LxKlogLock);
            return 0;

        case LX_SYSLOG_ACTION_SIZE_UNREAD:
            ExAcquireFastMutex(&LxKlogLock);
            for (Seq = LxKlogSyslogSeq; Seq < LxKlogNextSeq; Seq++)
                Result += LxKlogFormatSyslog(LxKlogRecords[Seq % LX_KLOG_MAX_RECORDS], Line, sizeof(Line));
            ExReleaseFastMutex(&LxKlogLock);
            return Result;

        default:
            return LX_KLOG_BUFFER_SIZE;
    }
}

VOID
LxKlogGetPrintk(
    _Out_writes_(4) PLONG Values)
{
    ExAcquireFastMutex(&LxKlogLock);
    Values[0] = LxKlogConsoleLevel;
    Values[1] = LxKlogDefaultMessageLevel;
    Values[2] = LxKlogMinimumConsoleLevel;
    Values[3] = LxKlogDefaultConsoleLevel;
    ExReleaseFastMutex(&LxKlogLock);
}

LONG
LxKlogWritePrintk(
    _In_reads_bytes_(Length) PCSTR Data,
    _In_ ULONG Length)
{
    LONG Values[4] = { LxKlogConsoleLevel, LxKlogDefaultMessageLevel, LxKlogMinimumConsoleLevel,
                       LxKlogDefaultConsoleLevel };
    ULONG Index = 0, Field = 0;

    while ((Index < Length) && (Field < 4))
    {
        LONG Value = 0;
        BOOLEAN Digits = FALSE;

        while ((Index < Length) && ((Data[Index] == ' ') || (Data[Index] == '\t') || (Data[Index] == '\n')))
            Index++;
        while ((Index < Length) && (Data[Index] >= '0') && (Data[Index] <= '9'))
        {
            Value = Value * 10 + (Data[Index++] - '0');
            Digits = TRUE;
        }
        if (!Digits)
            break;
        if ((Index < Length) && (Data[Index] != ' ') && (Data[Index] != '\t') && (Data[Index] != '\n'))
            return -LX_EINVAL;
        Values[Field++] = Value;
    }
    if (Field == 0)
        return -LX_EINVAL;
    ExAcquireFastMutex(&LxKlogLock);
    LxKlogConsoleLevel = Values[0];
    LxKlogDefaultMessageLevel = Values[1];
    LxKlogMinimumConsoleLevel = Values[2];
    LxKlogDefaultConsoleLevel = Values[3];
    ExReleaseFastMutex(&LxKlogLock);
    return 0;
}

LONG
LxKlogDmesgRestrictValue(VOID)
{
    return LxKlogDmesgRestrict;
}

VOID
LxKlogSetDmesgRestrict(
    _In_ LONG Value)
{
    InterlockedExchange(&LxKlogDmesgRestrict, Value);
}

PCSTR
LxKlogDevkmsgName(VOID)
{
    switch (LxKlogDevkmsgMode)
    {
        case LX_DEVKMSG_OFF:
            return "off";
        case LX_DEVKMSG_RATELIMIT:
            return "ratelimit";
        default:
            return "on";
    }
}

LONG
LxKlogSetDevkmsg(
    _In_reads_bytes_(Length) PCSTR Data,
    _In_ ULONG Length)
{
    while ((Length > 0) && ((Data[Length - 1] == '\n') || (Data[Length - 1] == ' ')))
        Length--;
    if ((Length == 2) && (strncmp(Data, "on", 2) == 0))
        InterlockedExchange(&LxKlogDevkmsgMode, LX_DEVKMSG_ON);
    else if ((Length == 3) && (strncmp(Data, "off", 3) == 0))
        InterlockedExchange(&LxKlogDevkmsgMode, LX_DEVKMSG_OFF);
    else if ((Length == 9) && (strncmp(Data, "ratelimit", 9) == 0))
        InterlockedExchange(&LxKlogDevkmsgMode, LX_DEVKMSG_RATELIMIT);
    else
        return -LX_EINVAL;
    return 0;
}
