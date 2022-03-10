#ifndef DEFINE_HPP
#define DEFINE_HPP

// The type of each counter in our vector clocks.
#define T unsigned int
// The maximum number of threads total.
// Used to specify VC sizes statically.
#define THREADS 3

// These allow you to selectively enable or disable each type of analysis.
// Disabling analyses we don't need can improve performance,
// since less needs to be tracked.
#define UAF
#define NPD
#define DF

#endif