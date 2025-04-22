#ifndef MLOP_HELPER_H
#define MLOP_HELPER_H

#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"
#include "bakshalipour_framework.h"
using namespace std; 

namespace knob
{
	extern uint32_t mlop_pref_degree;
	extern uint32_t mlop_num_updates;
	extern float 	mlop_l1d_thresh;
	extern float 	mlop_l2c_thresh;
	extern float 	mlop_llc_thresh;
	extern uint32_t	mlop_debug_level;
	extern int32_t ppf_perc_threshold_hi;
    extern int32_t ppf_perc_threshold_lo;
}

namespace mlop_ppf {

// Prefetch filter parameters
#define QUOTIENT_BIT  10
#define REMAINDER_BIT 6
#define HASH_BIT (QUOTIENT_BIT + REMAINDER_BIT + 1)
#define FILTER_SET (1 << QUOTIENT_BIT)

#define QUOTIENT_BIT_REJ  10
#define REMAINDER_BIT_REJ 8
#define HASH_BIT_REJ (QUOTIENT_BIT_REJ + REMAINDER_BIT_REJ + 1)
#define FILTER_SET_REJ (1 << QUOTIENT_BIT_REJ)

// Perceptron paramaters
#define PERC_ENTRIES 4096 //Upto 12-bit addressing in hashed perceptron
#define PERC_FEATURES_MLOP 6 
#define PERC_COUNTER_MAX 15 //-16 to +15: 5 bits counter 
// #define PERC_THRESHOLD_HI  -5
// #define PERC_THRESHOLD_LO  -15
#define POS_UPDT_THRESHOLD  90
#define NEG_UPDT_THRESHOLD -80

#define MAX_GHR_ENTRY 8
#define PAGES_TRACKED 6


enum FILTER_REQUEST {MLOP_L2C_PREFETCH, MLOP_LLC_PREFETCH, L2C_DEMAND, L2C_EVICT, MLOP_PERC_REJECT}; // Request type for prefetch filter

class PERCEPTRON
{
public:
    // Perc Weights
    int32_t perc_weights[PERC_ENTRIES][PERC_FEATURES_MLOP];

    // CONST depths for different features
    int32_t PERC_DEPTH[PERC_FEATURES_MLOP];

    PERCEPTRON()
    {
        cout << "\nInitialize PERCEPTRON" << endl;
        cout << "PERC_ENTRIES: " << PERC_ENTRIES << endl;
        cout << "PERC_FEATURES_MLOP: " << PERC_FEATURES_MLOP << endl;

        PERC_DEPTH[0] = 2048; //base_addr;
        PERC_DEPTH[1] = 4096; //cache_line;
        PERC_DEPTH[2] = 4096; //page_addr;
        PERC_DEPTH[3] = 4096; //ip_1 ^ ip_2 ^ ip_3;
        PERC_DEPTH[4] = 4096; // score 
        PERC_DEPTH[5] = 4096; // proportion of bit vector filled 

        for (int i = 0; i < PERC_ENTRIES; i++)
        {
            for (int j = 0; j < PERC_FEATURES_MLOP; j++)
            {
                perc_weights[i][j] = 0;
            }
        }
    }

    void perc_update(uint64_t check_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop, bool direction, int32_t perc_sum);
    int32_t perc_predict(uint64_t check_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop);
    void get_perc_index(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop, uint64_t perc_set[PERC_FEATURES_MLOP]);
};

class GLOBAL_REGISTER
{
public:
    // Global counters to calculate global prefetching accuracy
    uint64_t pf_useful,
        pf_issued,
        global_accuracy; // Alpha value in Section III. Equation 3

    // Global History Register (GHR) entries
    uint8_t valid[MAX_GHR_ENTRY];
    uint32_t offset[MAX_GHR_ENTRY];
    int  delta[MAX_GHR_ENTRY];

    uint64_t ip_0,
        ip_1,
        ip_2,
        ip_3;

    uint64_t page_tracker[PAGES_TRACKED];

    GLOBAL_REGISTER()
    {
        pf_useful = 0;
        pf_issued = 0;
        global_accuracy = 0;
        ip_0 = 0;
        ip_1 = 0;
        ip_2 = 0;
        ip_3 = 0;

        for (uint32_t i = 0; i < MAX_GHR_ENTRY; i++)
        {
            valid[i] = 0;
            offset[i] = 0;
            delta[i] = 0;
        }
    }

    void update_entry(uint32_t pf_sig, uint32_t pf_confidence, uint32_t pf_offset, int pf_delta);
    uint32_t check_entry(uint32_t page_offset);
};

class PREFETCH_FILTER
{
public:
    /* cross-reference pointers */
    PERCEPTRON *perc;
    GLOBAL_REGISTER *ghr;

    uint64_t remainder_tag[FILTER_SET],
        pc[FILTER_SET],
        pc_1[FILTER_SET],
        pc_2[FILTER_SET],
        pc_3[FILTER_SET],
        address[FILTER_SET];
    bool valid[FILTER_SET], // Consider this as "prefetched"
        useful[FILTER_SET]; // Consider this as "used"
    int32_t delta[FILTER_SET],
        scores[FILTER_SET],
        perc_sum[FILTER_SET];
    uint32_t bit_vec_props[FILTER_SET], 
        la_depth[FILTER_SET];

    uint64_t remainder_tag_reject[FILTER_SET_REJ],
        pc_reject[FILTER_SET_REJ],
        pc_1_reject[FILTER_SET_REJ],
        pc_2_reject[FILTER_SET_REJ],
        pc_3_reject[FILTER_SET_REJ],
        address_reject[FILTER_SET_REJ];
    bool valid_reject[FILTER_SET_REJ]; // Entries which the perceptron rejected
    int32_t delta_reject[FILTER_SET_REJ],
        perc_sum_reject[FILTER_SET_REJ], 
        scores_reject[FILTER_SET_REJ];
    uint32_t la_depth_reject[FILTER_SET_REJ], 
            bit_vec_prop_reject[FILTER_SET_REJ];

    PREFETCH_FILTER()
    {
        cout << endl
             << "Initialize PREFETCH FILTER" << endl;
        cout << "FILTER_SET: " << FILTER_SET << endl;

        for (uint32_t set = 0; set < FILTER_SET; set++)
        {
            remainder_tag[set] = 0;
            valid[set] = 0;
            useful[set] = 0;
        }
        for (uint32_t set = 0; set < FILTER_SET_REJ; set++)
        {
            valid_reject[set] = 0;
            remainder_tag_reject[set] = 0;
        }
    }

    bool check(uint64_t pf_addr, uint64_t base_addr, uint64_t ip, FILTER_REQUEST filter_request, int32_t score, uint32_t bit_vec_prop);
};
}

#endif