#include <iostream>
#include "mlop_ppf_helper.h"
#include "mlop_ppf.h"
#include "ppf_dev_helper.h"



namespace mlop_ppf {

uint64_t get_hash(uint64_t key)
{
    // Robert Jenkins' 32 bit mix function
    key += (key << 12);
    key ^= (key >> 22);
    key += (key << 4);
    key ^= (key >> 9);
    key += (key << 10);
    key ^= (key >> 2);
    key += (key << 7);
    key ^= (key >> 12);

    // Knuth's multiplicative method
    key = (key >> 3) * 2654435761;

    return key;
}

bool PREFETCH_FILTER::check(uint64_t check_addr, uint64_t base_addr, uint64_t ip, FILTER_REQUEST filter_request, int32_t score, uint32_t bit_vec_prop)
{
    uint64_t cache_line = check_addr >> LOG2_BLOCK_SIZE,
             hash = mlop_ppf::get_hash(cache_line);
	
	//MAIN FILTER
	uint64_t quotient = (hash >> REMAINDER_BIT) & ((1 << QUOTIENT_BIT) - 1),
             remainder = hash % (1 << REMAINDER_BIT);
	
	//REJECT FILTER
	uint64_t quotient_reject = (hash >> REMAINDER_BIT_REJ) & ((1 << QUOTIENT_BIT_REJ) - 1),
             remainder_reject = hash % (1 << REMAINDER_BIT_REJ);

    SPP_DP (
        cout << "[FILTER] check_addr: " << hex << check_addr << " check_cache_line: " << (check_addr >> LOG2_BLOCK_SIZE);
		cout << " request type: " << filter_request;
        cout << " hash: " << hash << dec << " quotient: " << quotient << " remainder: " << remainder << endl;
    );

    switch (filter_request) {
		
		case MLOP_PERC_REJECT: // To see what would have been the prediction given perceptron has rejected the PF
            if ((valid[quotient] || useful[quotient]) && remainder_tag[quotient] == remainder) { 
				// We want to check if the prefetch would have gone through had perc not rejected
				// So even in perc reject case, I'm checking in the accept filter for redundancy
                SPP_DP (
                    cout << "[FILTER] " << __func__ << " line is already in the filter check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
                );
                return false; // False return indicates "Do not prefetch"
            } else {
				valid_reject[quotient_reject] = 1;
				remainder_tag_reject[quotient_reject] = remainder_reject;

				// Logging perc features
				address_reject[quotient_reject] = base_addr;
				pc_reject[quotient_reject] = ip;
				pc_1_reject[quotient_reject] = ghr->ip_1;
				pc_2_reject[quotient_reject] = ghr->ip_2;
				pc_3_reject[quotient_reject] = ghr->ip_3;
				scores_reject[quotient_reject] = score; 
				bit_vec_prop_reject[quotient_reject] = bit_vec_prop;

				SPP_DP (
                    cout << "[FILTER] " << __func__ << " PF rejected by perceptron. Set valid_reject for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " remainder_tag: " << remainder_tag_reject[quotient_reject] << endl; 
					cout << " More Recorded Metadata: Addr: " << hex << address_reject[quotient_reject] << dec << " PC: " << pc_reject[quotient_reject] << " Delta: " << delta_reject[quotient_reject] << " Last Signature: " << last_signature_reject[quotient_reject] << " Current Signature: " << cur_signature_reject[quotient_reject] << " Confidence: " << confidence_reject[quotient_reject] << endl;
                );
			}
			break;
		
		case MLOP_L2C_PREFETCH:
            if ((valid[quotient] || useful[quotient]) && remainder_tag[quotient] == remainder) { 
                SPP_DP (
                    cout << "[FILTER] " << __func__ << " line is already in the filter check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
                );

                return false; // False return indicates "Do not prefetch"
            } else {

                valid[quotient] = 1;  // Mark as prefetched
                useful[quotient] = 0; // Reset useful bit
                remainder_tag[quotient] = remainder;

				// Logging perc features
				pc[quotient] = ip;
				pc_1[quotient] = ghr->ip_1;
				pc_2[quotient] = ghr->ip_2;
				pc_3[quotient] = ghr->ip_3;
				scores[quotient] = score;
				address[quotient] = base_addr; 
				bit_vec_props[quotient] = bit_vec_prop;
				
				SPP_DP (
                    cout << "[FILTER] " << __func__ << " set valid for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " remainder_tag: " << remainder_tag[quotient] << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
					cout << " More Recorded Metadata: Addr:" << hex << address[quotient] << dec << " PC: " << pc[quotient] << " Delta: " << delta[quotient] << " Last Signature: " << last_signature[quotient] << " Current Signature: " << cur_signature[quotient] << " Confidence: " << confidence[quotient] << endl;
                );
            }
            break;

        case MLOP_LLC_PREFETCH:
            if ((valid[quotient] || useful[quotient]) && remainder_tag[quotient] == remainder) { 
                SPP_DP (
                    cout << "[FILTER] " << __func__ << " line is already in the filter check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
                );

                return false; // False return indicates "Do not prefetch"
            } else {
                // NOTE: SPP_LLC_PREFETCH has relatively low confidence 
                // Therefore, it is safe to prefetch this cache line in the large LLC and save precious L2C capacity
                // If this prefetch request becomes more confident and SPP eventually issues SPP_L2C_PREFETCH,
                // we can get this cache line immediately from the LLC (not from DRAM)
                // To allow this fast prefetch from LLC, SPP does not set the valid bit for SPP_LLC_PREFETCH
				
				SPP_DP (
                    cout << "[FILTER] " << __func__ << " don't set valid for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
                );
            }
            break;

        case L2C_DEMAND:
            if ((remainder_tag[quotient] == remainder) && (useful[quotient] == 0)) {
                useful[quotient] = 1;
                if (valid[quotient]) {
					ghr->pf_useful++; // This cache line was prefetched by SPP and actually used in the program
				}

                SPP_DP (
                    cout << "[FILTER] " << __func__ << " set useful for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                    cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient];
                    cout << " ghr->pf_issued: " << ghr->pf_issued << " ghr->pf_useful: " << ghr->pf_useful << endl; 
					if (valid[quotient])
						cout << " Calling Perceptron Update (INC) as L2C_DEMAND was useful" << endl;
                );

                if (valid[quotient]) {
					// Prefetch leads to a demand hit
					perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], scores[quotient], bit_vec_props[quotient], 1, perc_sum[quotient]);
				}
            }
			//If NOT Prefetched
			if (!(valid[quotient] && remainder_tag[quotient] == remainder)) {
				// AND If Rejected by Perc
				if (valid_reject[quotient_reject] && remainder_tag_reject[quotient_reject] == remainder_reject) {
               		 SPP_DP (
               		     cout << "[FILTER] " << __func__ << " not doing anything for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
               		     cout << " quotient: " << quotient << " valid_reject:" << valid_reject[quotient_reject];
               		     cout << " ghr->pf_issued: " << ghr->pf_issued << " ghr->pf_useful: " << ghr->pf_useful << endl; 
			   		 	 cout << " Calling Perceptron Update (DEC) as a useful L2C_DEMAND was rejected and reseting valid_reject" << endl;
               		 );
					// Not prefetched but could have been a good idea to prefetch
					perc->perc_update(address_reject[quotient_reject], pc_reject[quotient_reject], pc_1_reject[quotient_reject], pc_2_reject[quotient_reject], pc_3_reject[quotient_reject], scores_reject[quotient_reject], bit_vec_prop_reject[quotient_reject], 0, perc_sum_reject[quotient_reject]);
					valid_reject[quotient_reject] = 0;
					remainder_tag_reject[quotient_reject] = 0;
				}
			}
            break;

        case L2C_EVICT:
            // Decrease global pf_useful counter when there is a useless prefetch (prefetched but not used)
            if (valid[quotient] && !useful[quotient]) {
				if (ghr->pf_useful) 
					ghr->pf_useful--;
				
				SPP_DP (
               		cout << "[FILTER] " << __func__ << " eviction for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
               		cout << " quotient: " << quotient << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
					cout << " Calling Perceptron Update (DEC) as L2C_DEMAND was not useful" << endl;
					cout << " Reseting valid_reject" << endl;
            	);

				// Prefetch leads to eviction
				perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], scores[quotient], bit_vec_props[quotient], 0, perc_sum[quotient]);
			}
            // Reset filter entry
            valid[quotient] = 0;
            useful[quotient] = 0;
            remainder_tag[quotient] = 0;

			// Reset reject filter too
			valid_reject[quotient_reject] = 0;
			remainder_tag_reject[quotient_reject] = 0;

            break;

        default:
            // Assertion
            cout << "[FILTER] Invalid filter request type: " << filter_request << endl;
            assert(0);
    }

    return true;
}

void PERCEPTRON::get_perc_index(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop, uint64_t perc_set[PERC_FEATURES]) {
{
	// Returns the imdexes for the perceptron tables
    uint64_t cache_line = base_addr >> LOG2_BLOCK_SIZE,
			 page_addr  = base_addr >> LOG2_PAGE_SIZE;

	int delta = 0; // fix this -- need to calculate something? idk what delta is 
	//int sig_delta = (cur_delta < 0) ? (((-1) * cur_delta) + (1 << (SIG_DELTA_BIT - 1))) : cur_delta;
	uint64_t  pre_hash[PERC_FEATURES];

	pre_hash[0] = base_addr;
	pre_hash[1] = cache_line;
	pre_hash[2] = page_addr;
	pre_hash[3] = ip_1 ^ (ip_2>>1) ^ (ip_3>>2);
	pre_hash[4] = ip ^ delta;
	pre_hash[5] = score; 
	pre_hash[6] = bit_vec_prop;

	for (int i = 0; i < PERC_FEATURES; i++) 
		perc_set[i] = (pre_hash[i]) % PERC_DEPTH[i]; // Variable depths
		SPP_DP (
			cout << "  Perceptron Set Index#: " << i << " = " <<  perc_set[i];
		);
	}
	SPP_DP (
		cout << endl;
	);	
}

int32_t	PERCEPTRON::perc_predict(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop)
{

	uint64_t perc_set[PERC_FEATURES];
	// Get the indexes in perc_set[]
	get_perc_index(base_addr, ip, ip_1, ip_2, ip_3, score, bit_vec_prop, perc_set);
	
	int32_t sum = 0;
	for (int i = 0; i < PERC_FEATURES; i++) {
		sum += perc_weights[perc_set[i]][i];	
		// Calculate Sum
	}
	SPP_DP (
		cout << " Sum of perceptrons: " << sum << " Prediction made: " << ((sum >= knob::ppf_perc_threshold_lo) ?  ((sum >= knob::ppf_perc_threshold_hi) ? FILL_L2 : FILL_LLC) : 0)  << endl;
	);
	// Return the sum
	return sum;
}

void PERCEPTRON::perc_update(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t score, uint32_t bit_vec_prop, bool direction, int32_t perc_sum)
{
	// SPP_DP (
	// 	int sig_delta = (cur_delta < 0) ? (((-1) * cur_delta) + (1 << (SIG_DELTA_BIT - 1))) : cur_delta;
	// 	cout << "[PERC_UPD] (Recorded) IP: " << ip << "  and  Memory Adress: " << hex << base_addr << endl;
	// 	cout << " Last Sig: " << last_sig << " Curr Sig: " << curr_sig << dec << endl;
	// 	cout << " Cur Delta: " << cur_delta << " Sign Delta: " << sig_delta << " Confidence: "<< confidence << " Update Direction: " << direction << endl;
	// 	cout << " ";
	// );

	uint64_t perc_set[PERC_FEATURES];
	// Get the perceptron indexes
	get_perc_index(base_addr, ip, ip_1, ip_2, ip_3, score, bit_vec_prop, perc_set);
	
	int32_t sum = 0;
	// Restore the sum that led to the prediction
	sum = perc_sum;
	
	if (!direction) { // direction = 1 means the sum was in the correct direction, 0 means it was in the wrong direction
		// Prediction wrong
		for (int i = 0; i < PERC_FEATURES; i++) {
			if (sum >= knob::ppf_perc_threshold_hi) {
				// Prediction was to prefectch -- so decrement counters
				if (perc_weights[perc_set[i]][i] > -1*(PERC_COUNTER_MAX+1) )
					perc_weights[perc_set[i]][i]--;
			}
			if (sum < knob::ppf_perc_threshold_hi) {
				// Prediction was to not prefetch -- so increment counters
				if (perc_weights[perc_set[i]][i] < PERC_COUNTER_MAX)
					perc_weights[perc_set[i]][i]++;
			}
		}
		SPP_DP (
			int differential = (sum >= knob::ppf_perc_threshold_hi) ? -1 : 1;
			cout << " Direction is: " << direction << " and sum is:" << sum;
			cout << " Overall Differential: " << differential << endl;
		);
	}
	if (direction && sum > NEG_UPDT_THRESHOLD && sum < POS_UPDT_THRESHOLD) {
		// Prediction correct but sum not 'saturated' enough
		for (int i = 0; i < PERC_FEATURES; i++) {
			if (sum >= knob::ppf_perc_threshold_hi) {
				// Prediction was to prefetch -- so increment counters
				if (perc_weights[perc_set[i]][i] < PERC_COUNTER_MAX)
					perc_weights[perc_set[i]][i]++;
			}
			if (sum < knob::ppf_perc_threshold_hi) {
				// Prediction was to not prefetch -- so decrement counters
				if (perc_weights[perc_set[i]][i] > -1*(PERC_COUNTER_MAX+1) )
					perc_weights[perc_set[i]][i]--;
			}
		}
		SPP_DP (
			int differential = 0;
			if (sum >= knob::ppf_perc_threshold_hi) differential =  1;
			if (sum  < knob::ppf_perc_threshold_hi) differential = -1;
			cout << " Direction is: " << direction << " and sum is:" << sum;
			cout << " Overall Differential: " << differential << endl;
		);
	}
}
}