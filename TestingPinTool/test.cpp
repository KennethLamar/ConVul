#include <cstdlib>
#include <pthread.h>

pthread_mutex_t lock;

// A test to ensure each function is correctly instrumented.
int main()
{
    int *ptr = new int();
    free(ptr);
    pthread_mutex_init(&lock, NULL);
    pthread_mutex_lock(&lock);
    pthread_mutex_unlock(&lock);
    return 0;
}