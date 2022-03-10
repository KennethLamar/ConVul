#ifndef CONVUL_HPP
#define CONVUL_HPP

#include <algorithm>
#include <cstdarg>
#include <map>
#include <set>
#include <vector>

#include <malloc.h>

#include "pin.H"
#include "define.hpp"

// Contains all ConVul logging and provides an interface for Pin.
class ConVulManager
{
    class Event;
    class Block;
    class Thread;
    class Memory;
    class Lock;

    class Lock
    {
    public:
        // The vector clock.
        T VC[THREADS];
        // The address of this lock.
        uintptr_t addr;
        // Ensures only one thread is interacting with the lock VC at a time.
        // NOTE: This may be unecessary, as the actual lock may effectively
        // prevent other threads from interacting with the VC at the same time.
        // We do this just to be safe.
        LEVEL_BASE::PIN_RWMUTEX localLock;

        Lock(uintptr_t addr);
    };

    class Block
    {
    public:
        // The thread that created this block.
        size_t threadID;
        // The trace index where the lock was acquired.
        size_t acqIdx = 0;
        // The trace index where the lock was released.
        size_t relIdx = 0;
        // A pointer to the object tracking the lock.
        // This is useful for distinguishing between blocks for different locks.
        Lock *lock = NULL;

        Block(size_t threadID, size_t acqIdx, Lock *lock);
    };

    class Event
    {
    public:
        // A tracked event operation type.
        enum OpType
        {
            read = 0,
            write,
            free,
            lock,
            unlock,
        } typedef OpType;

        // The thread that ran this event.
        size_t threadID;
        // The index of this event in the per-thread trace log.
        size_t traceIdx;
        // The type of the event. Always one of our tracked events.
        OpType type;
        // The address associated with this operation.
        uintptr_t addr;
        // The address of this event's associated instruction pointer.
        // Used to report line numbers when a vulnerability is found.
        ADDRINT IP;
        // Context is used to report an event backtrace.
        CONTEXT *ctxt;
        // All blocks associated with this event, keyed by lock address.
        std::map<Lock *, Block *> blocks;
        // The vector clock.
        // Essential for testing for exchangeable events.
        T VC[THREADS];
#ifdef DF
        uintptr_t writeVal;
#endif

        Event(size_t threadID, uintptr_t addr, size_t traceIdx, ADDRINT IP, const CONTEXT *ctxt);

        // Compare vector clocks between two events.
        // Returns:
        //  0 if they are equal.
        // -1 if this happens before e.
        //  1 if e happens before this.
        // -2 if VC is empty.
        //  2 if they are concurrent.
        int compare(Event *e);
        // Identifies if events have a sync edge distance <= 3.
        bool isExchangeable(Event *e);
        // Print out the event associated with a log.
        void printEvent();
    };

    class Memory
    {
    public:
        // The address of the memory location.
        uintptr_t addr;
        // NOTE: Memory has no vector clocks because we aren't checking
        // for HBR violations.

#ifdef UAF
        // All events that access this memory location.
        std::set<Event *> events;
#endif

#ifdef NPD
        // NOTE: These are for pointers only. Pointer typing would help here.

        // Keep track of events associated with this memory location.
        std::set<Event *> readEvents;
        std::set<Event *> writeNULLEvents;
        std::set<Event *> writeNonNULLEvents;

        // NOTE: Unused. Event vector clocks are sufficient.
        // // A read vector clock
        // T pReadVC[THREADS];
        // // A non-NULL write vector clock for NPD.
        // T pWriteVC[THREADS];
        // // A NULL write vector clock for NPD.
        // T pWriteNULLVC[THREADS];
#endif

#ifdef DF
        // All memory locations that point to us.
        // NOTE: This changes dynamically at run-time, with pointers being added and removed.
        // Consider copying this data, as it is now, to the event?
        std::set<Memory *> pointers;
        // All events that free us.
        std::set<Event *> freeEvents;
        // The event that last wrote a pointer to this memory location.
        // NOTE: This changes dynamically at run-time, with the latest event always updating.
        Event *pEvent = NULL;
#endif

        Memory(uintptr_t addr);
    };

    class Thread
    {
    public:
        // A trace of events performed by the thread.
        std::vector<Event *> trace;
        // The blocks of each lock currently held by the thread,
        // keyed by lock address.
        // NOTE: This changes dynamically at run-time, with blocks being added and removed.
        // However, this is thread-local and thus doesn't have any special synchronization or analysis concerns.
        std::map<Lock *, Block *> blocks;
        // The Pin-provided ID of the thread.
        size_t threadID;
        // The vector clock.
        T VC[THREADS];

        Thread(size_t threadID);
    };

    // Runs on every tracked event.
    static Event *onEvent(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr);
    // Runs on every read and write.
    static Memory *onMemAccess(size_t threadID, uintptr_t addr, Event *e);

protected:
    // Our thread objects, indexed by Pin's provided threadIDs.
    static std::vector<Thread *> threads;
    // A map to all tracked memory locations, keyed by memory address.
    static std::map<uintptr_t, Memory *> memMap;
    static LEVEL_BASE::PIN_RWMUTEX memLock;
    // A map to all tracked locks, keyed by memory address.
    static std::map<uintptr_t, Lock *> lockMap;
    // TODO: Consider adding per-location locks, rather than one lock for all memory accesses.
    static LEVEL_BASE::PIN_MUTEX lockLock;
    // Used to regulate printing so messages are all properly grouped.
    static LEVEL_BASE::PIN_MUTEX printLock;

public:
    ConVulManager();
    // NOTE: All of this is static because Pin doesn't like being told to call
    // instances of functions.
    // This can be fixed by having wrappers call the ConVulManager instance.
    static void onRead(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr, bool isDeref);
    static void onWrite(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr, uintptr_t val);
    static void onFree(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr);
    static void onAcq(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr);
    static void onRel(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr);
    // Print the final report.
    static void endReport();
    // Reports the existence of a vulnerability between events.
    static void report(const char *errMsg, size_t count, ...);
};

#endif
