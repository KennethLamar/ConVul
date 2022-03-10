#include "ConVul.hpp"

ConVulManager::Lock::Lock(uintptr_t addr)
{
    LEVEL_BASE::PIN_RWMutexInit(&localLock);
    this->addr = addr;
    // All clocks are initialized to 0.
    for (size_t i = 0; i < THREADS; i++)
    {
        VC[i] = 0;
    }
}

ConVulManager::Block::Block(size_t threadID, size_t acqIdx, Lock *lock)
{
    this->threadID = threadID;
    this->acqIdx = acqIdx;
    this->lock = lock;
}

ConVulManager::Memory::Memory(uintptr_t addr)
{
    this->addr = addr;
    // // All clocks are initialized to 0.
    // for (size_t i = 0; i < THREADS; i++)
    // {
    //     VC[i] = 0;
    //     pReadVC[i] = 0;
    //     pWriteVC[i] = 0;
    //     pWriteNULLVC[i] = 0;
    // }
}

ConVulManager::Thread::Thread(size_t threadID)
{
    // Set the thread ID.
    this->threadID = threadID;
    // All clocks are initialized to 1.
    for (size_t i = 0; i < THREADS; i++)
    {
        VC[i] = 1;
    }
}

ConVulManager::ConVulManager()
{
    // Initialize our threads.
    for (size_t i = 0; i < THREADS; i++)
    {
        threads.push_back(new Thread(i));
    }
    // Initialize our analysis locks.
    LEVEL_BASE::PIN_RWMutexInit(&memLock);
    LEVEL_BASE::PIN_MutexInit(&lockLock);
    LEVEL_BASE::PIN_MutexInit(&printLock);
}

ConVulManager::Event::Event(size_t threadID, uintptr_t addr, size_t traceIdx,
                            ADDRINT IP, const CONTEXT *ctxt)
{
    this->threadID = threadID;
    this->addr = addr;
    this->traceIdx = traceIdx;
    this->IP = IP;
    this->ctxt = (CONTEXT *)malloc(sizeof(CONTEXT));
    PIN_SaveContext(ctxt, this->ctxt);
    // Copy over all active blocks.
    this->blocks = ConVulManager::threads[threadID]->blocks;
    // All clocks are initialized to 0.
    for (size_t i = 0; i < THREADS; i++)
    {
        VC[i] = 0;
    }
}

// Compare vector clocks between two events.
// Returns:
//  0 if they are equal.
// -1 if this happens before e.
//  1 if e happens before this.
// -2 if VC is empty.
//  2 if they are concurrent.
int ConVulManager::Event::compare(Event *e)
{
    // Notes:
    // -2: Case where THREADS = 0. Shouldn't happen in practice.
    //  0: For all i, this->VC[i] == e->VC[i]
    // -1: For all i, this->VC[i] <= e->VC[i]
    //  1: For all i, this->VC[i] >= e->VC[i]
    //  2: Everything else.

    // Return value. Initially -2.
    int ret = -2;
    // Check the whole vector clock.
    for (size_t i = 0; i < THREADS; i++)
    {
        switch (ret)
        {
        // If we haven't updated the initial value yet.
        case -2:
            // If the first comparison suggests our clock is less than e's clock.
            if (this->VC[i] < e->VC[i])
            {
                // Then set our return value to indicate this possibility.
                ret = -1;
            }
            // If the first comparison suggests our clock is greater than e's clock.
            else if (this->VC[i] > e->VC[i])
            {
                // Then set our return value to indicate this possibility.
                ret = 1;
            }
            // If the first comparison suggests they are equal.
            else
            {
                // Then set our return value to indicate this possibility.
                ret = 0;
            }
            break;
        // If we think our clock is less than e's clock.
        case -1:
            // If the clocks are less than or equal to in all cases, then this will hold.

            // If our next comparison violates that belief.
            if (this->VC[i] > e->VC[i])
            {
                // The clocks are concurrent.
                return 2;
            }

            break;
        // If we think our clock is greater than e's clock.
        case 1:
            // If the clocks are greater than or equal to in all cases, then this will hold.

            // If our next comparison violates that belief.
            if (this->VC[i] < e->VC[i])
            {
                // The clocks are concurrent.
                return 2;
            }
            break;
        // If we think our clock is equal to e's clock.
        case 0:
            // If the next comparison suggests our clock is less than e's clock.
            if (this->VC[i] < e->VC[i])
            {
                // Then set our return value to indicate this possibility.
                ret = -1;
            }
            // If the next comparison suggests our clock is greater than e's clock.
            else if (this->VC[i] > e->VC[i])
            {
                // Then set our return value to indicate this possibility.
                ret = 1;
            }
            // Otherwise they are still believed to be equal.
            break;
        // They are concurrent.
        case 2:
            return ret;
        default:
            report("Invalid return type!", 0);
            break;
        }
    }
    return ret;
}

// NOTE: Could rework this to inform of HBR.
// This would speed up searches for exchangeable events.
bool ConVulManager::Event::isExchangeable(Event *e)
{
    // Verify a HBR for these events.
    int hbr = this->compare(e);
    if (hbr != -1 && hbr != 1)
    {
        return true;
    }

    // Determine the order of the two events.
    Event *e1 = ((hbr == -1) ? this : e);
    Event *e2 = ((hbr == 1) ? this : e);

    // Check this relationship for each lock.
    for (std::pair<Lock *, Block *> pair : e2->blocks)
    {
        Lock *lock = pair.first;
        Block *block = pair.second;

        // We don't care about blocks that aren't shared between events.
        if (e1->blocks.count(lock) == 0)
        {
            continue;
        }

        // Get eAny.
        Event *eAny = threads[block->threadID]->trace[block->acqIdx - 1];

        // bool isExchangeable = true;
        // Check for HBR.
        int cmp = eAny->compare(e1);
        // If there is no clear HBR for these events, in either order.
        if (cmp != -1 && cmp != 1)
        {
            return true;

            // None of this is needed. Block tracking lets us easily verify
            // that both events are protected by the same locks.
            // // If our lock's VC is equal to our e1 VC.
            // LEVEL_BASE::PIN_RWMutexReadLock(&block->lock->localLock);
            // for (size_t i = 0; i < THREADS; i++)
            // {
            //     // Determines whether the lock, l is the same between
            //     // events eRel and eAcq.
            //     if (block->lock->VC[i] != e1->VC[i])
            //     {
            //         isExchangeable = false;
            //         break;
            //     }
            // }
            // LEVEL_BASE::PIN_RWMutexUnlock(&block->lock->localLock);
            // // If the flag wasn't set false, then this event is exchangeable.
            // if (isExchangeable)
            // {
            //     return true;
            // }
        }
    }
    return false;
}

void ConVulManager::Event::printEvent()
{
    // Type
    const char *typeString;
    switch (type)
    {
    case read:
        typeString = "Read";
        break;
    case write:
#ifdef DF
        if (writeVal == (uintptr_t)NULL)
        {
            typeString = "NULL Write";
        }
        else
        {
            typeString = "Write";
        }
#else
        typeString = "Write";
#endif
        break;
    case free:
        typeString = "Free";
        break;
    case lock:
        typeString = "Lock";
        break;
    case unlock:
        typeString = "Unlock";
        break;
    default:
        typeString = "INVALID";
        break;
    }

    // Source code location.
    int column;
    int line;
    std::string fileName;
    LEVEL_PINCLIENT::PIN_LockClient();
    LEVEL_PINCLIENT::PIN_GetSourceLocation(IP, &column, &line, &fileName);
    LEVEL_PINCLIENT::PIN_UnlockClient();

    // Blocks?
    // Vector Clocks?

    // Print the report.
    printf("%-10s at address %p on thread %2zu at trace index %zu\n",
           typeString, (void *)addr, threadID, traceIdx);
    if (fileName.length() <= 0)
    {
        printf("\tin a file missing debug symbols.\n");
    }
    else
    {
        printf("\tin %s:%d\n", fileName.c_str(), line);
    }
    // // TODO: Unfortunately, some backtrace calls cause Pin to segfault. We disable the offending code.
    // // Now print the associated backtrace too.
    // void *buf[128];
    // LEVEL_PINCLIENT::PIN_LockClient();
    // size_t btSize = LEVEL_PINCLIENT::PIN_Backtrace(ctxt, buf, sizeof(buf) / sizeof(buf[0]));
    // for (size_t i = 0; i < btSize; i++)
    // {
    //     LEVEL_PINCLIENT::PIN_GetSourceLocation((ADDRINT)buf[i], &column, &line, &fileName);
    //     if (fileName.length() <= 0)
    //     {
    //         printf("\tfrom a file missing debug symbols.\n");
    //     }
    //     else
    //     {
    //         printf("\tfrom %s:%d\n", fileName.c_str(), line);
    //     }
    // }
    // LEVEL_PINCLIENT::PIN_UnlockClient();
}

void ConVulManager::report(const char *errMsg, size_t count, ...)
{
    // Acquire the print lock.
    LEVEL_BASE::PIN_MutexLock(&printLock);
    // Print the error message.
    printf("%s\n", errMsg);
    // If there are no events passed.
    if (count <= 0)
    {
        // Release the print lock.
        LEVEL_BASE::PIN_MutexUnlock(&printLock);
        // Nothing more to do.
        return;
    }
    printf("The following events were involved:\n");
    va_list valist;
    // Initialize the valist.
    va_start(valist, count);
    // Access all the arguments assigned to valist.
    for (size_t i = 0; i < count; i++)
    {
        Event *e = va_arg(valist, Event *);
        if (e != NULL)
        {
            e->printEvent();
        }
        else
        {
            printf("NULL event.\n");
        }
    }
    printf("\n");
    // Clean memory reserved for valist.
    va_end(valist);

    // Release the print lock.
    LEVEL_BASE::PIN_MutexUnlock(&printLock);
}

void ConVulManager::endReport()
{
    // Acquire the print lock.
    LEVEL_BASE::PIN_MutexLock(&printLock);
    printf("End evaluation.\n");
    size_t max = 0;
    for (Thread *thread : threads)
    {
        for (size_t i = 0; i < THREADS; i++)
        {
            max = thread->VC[i] > max ? thread->VC[i] : max;
        }
    }
    printf("Max VC value: %zu\n", max);
    // Release the print lock.
    LEVEL_BASE::PIN_MutexUnlock(&printLock);
}

// Called on every tracked event.
ConVulManager::Event *ConVulManager::onEvent(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr)
{
    // Catch invalid thread IDs.
    // This is a sign THREADS isn't big enough.
    if (threadID >= THREADS)
    {
        char *s = (char *)malloc(64 * sizeof(char));
        sprintf(s, "thread ID %zu >= THREADS %d", threadID, THREADS);
        report(s, 0);
        free(s);
    }

    // Increment the process's local time by 1.
    threads[threadID]->VC[threadID]++;

    // Create the new event.
    Event *e = new Event(threadID, addr, threads[threadID]->trace.size(), IP, ctxt);
    if (e == NULL)
    {
        report("Failed to allocate new event.", 0);
    }
    threads[threadID]->trace.push_back(e);

    // Set event VC so exchangeable checks work.
    // NOTE: This isn't explicitly laid out in the paper.
    for (size_t i = 0; i < THREADS; i++)
    {
        e->VC[i] = threads[threadID]->VC[i];
    }

    return e;
}

// Called by every memory access, both reads and writes.
ConVulManager::Memory *ConVulManager::onMemAccess(size_t threadID, uintptr_t addr, Event *e)
{
    LEVEL_BASE::PIN_RWMutexWriteLock(&memLock);
    // If the memory tracker doesn't exist already.
    if (!memMap.count(addr))
    {
        // Initialize a new memory tracker.
        memMap[addr] = new Memory(addr);
    }

#ifdef UAF
    // Add this event to the tracked list.
    memMap[addr]->events.insert(e);

    // Update the event's vector clock.
    // NOTE: This is done for UAF, but it's redundant.
    // We already track vector clocks for all events.
    //e->VC[threadID] = threads[threadID]->VC[threadID];
#endif

    return memMap[addr];
}

void ConVulManager::onRead(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr, bool isDeref)
{
    Event *e = onEvent(threadID, IP, ctxt, addr);
    e->type = Event::OpType::read;
#ifdef NPD
    Memory *mem = onMemAccess(threadID, addr, e);
#else
    onMemAccess(threadID, addr, e);
#endif

#ifdef NPD
    // Ignore non-pointer events.
    if (!isDeref)
    {
        LEVEL_BASE::PIN_RWMutexUnlock(&memLock);
        return;
    }
    // If there are NULL and non-NULL writes to this memory location.
    if (mem->writeNonNULLEvents.size() && mem->writeNULLEvents.size())
    {
        // Iterate over every combination of both.
        for (Event *nNul : mem->writeNonNULLEvents)
        {
            assert(nNul != NULL);
            for (Event *nul : mem->writeNULLEvents)
            {
                assert(nul != NULL);
                // If we find that any NULL write is exchangeable with a non-NULL write.
                if (nNul->isExchangeable(nul))
                {
                    // Report NPD.
                    report("NPD detected.", 3, nul, e, nNul);
                }
            }
            // If our current read is exchangeable with a non-NULL write.
            if (e->isExchangeable(nNul))
            {
                // It is possible that events happen in the folowing order:
                // NULL write, read, non-NULL write. This is a NPD bug.
                // We don't know which NULL write in this case, just that there is one.

                // Report NPD.
                report("NPD detected between unknown NULL write and these events.", 2, e, nNul);
            }
        }
    }
    // This pointer event should be tracked.
    mem->readEvents.insert(e);
#endif
    LEVEL_BASE::PIN_RWMutexUnlock(&memLock);
}

void ConVulManager::onWrite(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr, uintptr_t val)
{
    Event *e = onEvent(threadID, IP, ctxt, addr);
    e->type = Event::OpType::write;
#if defined(NPD) || defined(DF)
    Memory *mem = onMemAccess(threadID, addr, e);
#else
    onMemAccess(threadID, addr, e);
#endif

#ifdef NPD
    if ((void *)val == NULL)
    {
        // For each event that reads from the same memory location.
        for (Event *readEvent : mem->readEvents)
        {
            assert(readEvent != NULL);
            // If it's exchangeable with this NULL write.
            if (e->isExchangeable(readEvent))
            {
                // Report NPD.
                report("NPD detected.", 2, e, readEvent);
            }
        }
        // This event should be tracked.
        mem->writeNULLEvents.insert(e);
    }
    else
    {
        // This event should be tracked.
        mem->writeNonNULLEvents.insert(e);
    }
#endif
#ifdef DF
    // Remove p from each of these memory locations' pointer maps.
    // The value, p, in our memory location, m, no longer points to any of them.
    // Standard, unoptimized approach used in the paper.
    // for (std::pair<uintptr_t, Memory *> pair : memMap)
    // {
    //     pair.second->pointers.erase(mem);
    // }

    // This refined approach tracks the last event to write a pointer at m.
    // That way, we can just erase the associated memory address from the set.
    // The insight is that this pointer can only ever point to one location at a time.

    // If an event wrote here in the past.
    if (mem->pEvent != NULL)
    {
        memMap[mem->pEvent->writeVal]->pointers.erase(mem);
    }

    // If the memory tracker doesn't exist already.
    if (!memMap.count(val))
    {
        // Initialize a new memory tracker.
        memMap[val] = new Memory(val);
    }
    // Add our memory location to address val's pointer list.
    memMap[val]->pointers.insert(mem);
    // Store the last event to write a pointer to this memory address.
    mem->pEvent = e;
    // Ensure these match.
    // This should always be true.
    if (mem->addr != e->addr)
    {
        char *s = (char *)malloc(64 * sizeof(char));
        sprintf(s, "mem->addr = %p, e->addr = %p",
                (void *)mem->addr, (void *)e->addr);
        report(s, 0);
        free(s);
    }
    // Keep track of what value was written by this event for later use.
    e->writeVal = val;
#endif
    LEVEL_BASE::PIN_RWMutexUnlock(&memLock);
}

void ConVulManager::onFree(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr)
{
    Event *e = onEvent(threadID, IP, ctxt, addr);
    e->type = Event::OpType::free;

    LEVEL_BASE::PIN_RWMutexWriteLock(&memLock);
#ifdef UAF
    // NOTE: May need instrument malloc to get this information. May need to also consider calloc and realloc to be comprehensive.
    // NOTE: We will assume we only freed at exactly matching addresses.
    // This is an approximation, but improves performance.
    size_t sz = 1; //malloc_usable_size((void *)addr);
    // For each possible address offset.
    // NOTE: Potentially consider accesses to earlier addresses.
    // Depending on the size of them, they may overlap too.
    for (size_t i = 0; i < sz; i++)
    {
        // If the address has not been seen.
        if (!memMap.count(addr + i))
        {
            continue;
        }
        Memory *mem = memMap[addr + i];
        // Check for events that are exchangable.
        for (Event *eMem : mem->events)
        {
            if (eMem->isExchangeable(e))
            {
                // Report UAF.
                report("UAF detected.", 2, eMem, e);
            }
        }
    }
#endif
#ifdef DF
    if (!memMap.count(addr))
    {
        // Initialize a new memory tracker.
        memMap[addr] = new Memory(addr);
    }
    Memory *mem = memMap[addr];
    if (mem == NULL)
    {
        report("Failed to retrieve valid memory location.", 0);
    }
    for (Memory *pointer : mem->pointers)
    {
        // The event that set the pointer.
        Event *pEvent = pointer->pEvent;
        // Ensure it actually set the pointer.
        // This should always be true.
        if (pEvent->addr != pointer->addr)
        {
            char *s = (char *)malloc(64 * sizeof(char));
            sprintf(s, "pEvent->addr = %p, pointer->addr = %p",
                    (void *)pEvent->addr, (void *)pointer->addr);
            report(s, 0);
            free(s);
        }
        // For each event that freed p.
        for (Event *freeEvent : pointer->freeEvents)
        {
            // If the free event is exchangeable with the one that set p.
            if (freeEvent->isExchangeable(pEvent))
            {
                // Report DF.
                report("DF detected.", 3, e, freeEvent, pEvent);
            }
            // If the event that set p is exchangeable with the current event.
            else if (pEvent->isExchangeable(e))
            {
                // Report DF.
                report("DF detected.", 3, freeEvent, e, pEvent);
            }
        }
    }
    // Add this latest event to our list of frees for this memory location.
    mem->freeEvents.insert(e);
#endif
    LEVEL_BASE::PIN_RWMutexUnlock(&memLock);
}

void ConVulManager::onAcq(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr)
{
    Event *e = onEvent(threadID, IP, ctxt, addr);
    e->type = Event::OpType::lock;

    Lock *lock;
    // If the lock doesn't exist already.
    LEVEL_BASE::PIN_MutexLock(&lockLock);
    if (!lockMap.count(addr))
    {
        // Initialize a new lock.
        lockMap[addr] = new Lock(addr);
    }
    // Retrieve the lock from the map.
    lock = lockMap[addr];
    LEVEL_BASE::PIN_MutexUnlock(&lockLock);
    if (lock == NULL)
    {
        report("Failed to retrieve a valid lock.", 0);
    }

    LEVEL_BASE::PIN_RWMutexReadLock(&lock->localLock);
    // Update the thread's VC.
    for (size_t i = 0; i < THREADS; i++)
    {
        threads[threadID]->VC[i] = std::max(threads[threadID]->VC[i], lock->VC[i]);
    }
    LEVEL_BASE::PIN_RWMutexUnlock(&lock->localLock);

    // Track a new block associated with this lock.
    Block *block = new Block(threadID, e->traceIdx, lock);
    // Associate the block with the executing thread.
    threads[threadID]->blocks.insert(std::pair<Lock *, Block *>(lock, block));
}

void ConVulManager::onRel(size_t threadID, ADDRINT IP, const CONTEXT *ctxt, uintptr_t addr)
{
    Event *e = onEvent(threadID, IP, ctxt, addr);
    e->type = Event::OpType::unlock;

    Lock *lock;
    // If the lock doesn't exist already.
    LEVEL_BASE::PIN_MutexLock(&lockLock);
    if (!lockMap.count(addr))
    {
        // Initialize a new lock.
        lockMap[addr] = new Lock(addr);
    }
    // Retrieve the lock from the map.
    lock = lockMap[addr];
    LEVEL_BASE::PIN_MutexUnlock(&lockLock);
    if (lock == NULL)
    {
        report("Failed to retrieve a valid lock.", 0);
    }

    LEVEL_BASE::PIN_RWMutexWriteLock(&lock->localLock);
    // Update the lock's VC.
    for (size_t i = 0; i < THREADS; i++)
    {
        lock->VC[i] = std::max(threads[threadID]->VC[i], lock->VC[i]);
    }
    LEVEL_BASE::PIN_RWMutexUnlock(&lock->localLock);

    // Get the block from the list.
    // TODO: Handle the case where this block may not be valid.
    // This only happens if the program has a bug in its lock implementation.
    Block *block = threads[threadID]->blocks[lock];
    // Update the block with the corresponding release index.
    block->relIdx = e->traceIdx;
    // Remove the block from our list of active blocks.
    // NOTE: The locks are still referenced by events, making cleanup harder.
    threads[threadID]->blocks.erase(lock);
}

std::vector<ConVulManager::Thread *> ConVulManager::threads;
std::map<uintptr_t, ConVulManager::Memory *> ConVulManager::memMap;
std::map<uintptr_t, ConVulManager::Lock *> ConVulManager::lockMap;

LEVEL_BASE::PIN_RWMUTEX ConVulManager::memLock;
LEVEL_BASE::PIN_MUTEX ConVulManager::lockLock;
LEVEL_BASE::PIN_MUTEX ConVulManager::printLock;