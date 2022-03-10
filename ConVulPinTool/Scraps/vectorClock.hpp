#ifndef VECTORCLOCK_HPP
#define VECTORCLOCK_HPP

// This vector clock implementation is based on happens-before relation checking
// designed for Djit+ in the paper "MultiRace: Efficient on-the-fly data race
// detection in multithreaded C++ programs".
// NOTE: Clock updates are not atomic, but they should mostly be protected by a
// lock, so it should be fine, I guess.

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>

// Each thread gets a vector clock.
// T: The data type of our clocks.
// THREADS: The number of shared memory threads tracked by the vector clocks.
template <typename T, size_t THREADS>
class VectorClockT
{
    // The thread ID associated with this vector clock.
    // Used to identify the local clock to update.
    size_t threadID;
    std::array<T, THREADS> st;

    VectorClockT(size_t threadID);
    // Runs each time a processor experiences an internal event.
    void event();
};

// Each shared memory location gets a vector clock.
// T: The data type of our clocks.
// THREADS: The number of shared memory threads tracked by the vector clocks.
template <typename T, size_t THREADS>
class VectorClockM
{
    // Read vector clock.
    std::array<T, THREADS> vr;
    // Write vector clock.
    std::array<T, THREADS> vw;

    VectorClockM();
    // TODO: We only need to run this for the first read after a lock is acquired.
    void read(VectorClockT<T, THREADS> &clockT);
    // TODO: We only need to run this for the first write after a lock is acquired.
    void write(VectorClockT<T, THREADS> &clockT);
};

// Each lock gets a vector clock.
// T: The data type of our clocks.
// THREADS: The number of shared memory threads tracked by the vector clocks.
template <typename T, size_t THREADS>
class VectorClockL
{
    std::array<T, THREADS> st;

    VectorClockL();
    // Call this whenever the lock is released.
    void release(VectorClockT<T, THREADS> &clockT);
    // Call this whenever the lock is acquired.
    void acquire(VectorClockT<T, THREADS> &clockT);
};

#endif