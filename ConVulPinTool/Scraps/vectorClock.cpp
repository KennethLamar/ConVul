#include "vectorClock.hpp"

template <typename T, size_t THREADS>
VectorClockT<T, THREADS>::VectorClockT(size_t threadID)
{
    // We cannot assign a thread ID larger than the number of threads.
    assert(threadID < THREADS);
    // Set the threadID associated with this clock.
    // That way, we know which index represents our local time.
    this->threadID = threadID;
    // All clocks are initialized to 1.
    st.fill(1);
    return;
}
// Runs each time a processor experiences an internal event.
template <typename T, size_t THREADS>
void VectorClockT<T, THREADS>::event()
{
    // Increment the process's local time by 1.
    st[threadID]++;
    return;
}

template <typename T, size_t THREADS>
VectorClockM<T, THREADS>::VectorClockM()
{
    // All clocks are initialized to 0.
    vr.fill(0);
    vw.fill(0);
    return;
}
// NOTE: We only need to run this for the first read after a lock is acquired.
template <typename T, size_t THREADS>
void VectorClockM<T, THREADS>::read(VectorClockT<T, THREADS> &clockT)
{
    vr[clockT.threadID] = clockT.st[clockT.threadID];
    // NOTE: Seemingly no need to do this detection in ConVul. We will use clocks to identify exchangeability, not HBR.
    for (size_t i = 0; i < THREADS; i++)
    {
        if (vw[i] > clockT.st[i])
        {
            // Report a race.
            printf("Violation of happens before relation!\n");
        }
    }
    return;
}
// NOTE: We only need to run this for the first write after a lock is acquired.
template <typename T, size_t THREADS>
void VectorClockM<T, THREADS>::write(VectorClockT<T, THREADS> &clockT)
{
    vw[clockT.threadID] = clockT.st[clockT.threadID];
    // NOTE: Seemingly no need to do this detection in ConVul. We will use clocks to identify exchangeability, not HBR.
    for (size_t i = 0; i < THREADS; i++)
    {
        if (vw[i] > clockT.st[i] ||
            vr[i] > clockT.st[i])
        {
            // Report a race.
            printf("Violation of happens before relation!\n");
        }
    }
    return;
}

template <typename T, size_t THREADS>
VectorClockL<T, THREADS>::VectorClockL()
{
    // All clocks are initialized to 0.
    st.fill(0);
    return;
}
// Call this whenever the lock is released.
template <typename T, size_t THREADS>
void VectorClockL<T, THREADS>::release(VectorClockT<T, THREADS> &clockT)
{
    // The associated thread increments its local clock.
    clockT.event();
    // Find and update the max clock between vectors.
    for (size_t i = 0; i < THREADS; i++)
    {
        // Keep the maximum perceived clock value of each thread.
        st[i] = max(clockT.st[i], st[i]);
    }
}
// Call this whenever the lock is acquired.
template <typename T, size_t THREADS>
void VectorClockL<T, THREADS>::acquire(VectorClockT<T, THREADS> &clockT)
{
    // Find and update the max clock between vectors.
    for (size_t i = 0; i < THREADS; i++)
    {
        // Keep the maximum perceived clock value of each thread.
        clockT.st[i] = max(clockT.st[i], st[i]);
    }
}