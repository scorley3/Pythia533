#include <iostream>
#include "cache.h"
#include "champsim.h"
#include "bingo_ppf.h"

using namespace bingo_ppf;

namespace knob
{
   extern uint32_t bingo_region_size;
	extern uint32_t bingo_pattern_len;
	extern uint32_t bingo_pc_width;
	extern uint32_t bingo_min_addr_width;
	extern uint32_t bingo_max_addr_width;
	extern uint32_t bingo_ft_size;
	extern uint32_t bingo_at_size;
	extern uint32_t bingo_pht_size;
	extern uint32_t bingo_pht_ways;
	extern uint32_t bingo_pf_streamer_size;
	extern uint32_t bingo_debug_level;
   extern float    bingo_l1d_thresh;
   extern float    bingo_l2c_thresh;
   extern float    bingo_llc_thresh;
   extern string   bingo_pc_address_fill_level;

   extern int32_t ppf_perc_threshold_hi;
   extern int32_t ppf_perc_threshold_lo;

  }

void Bingo_PPF::init_knobs() {
   assert((knob::bingo_region_size >> LOG2_BLOCK_SIZE) == knob::bingo_pattern_len);
}

void Bingo_PPF::init_stats() {

}

Bingo_PPF::Bingo_PPF(string type, CACHE *cache) :
   Prefetcher(type), parent(cache),
   pattern_len(knob::bingo_pattern_len), filter_table(knob::bingo_ft_size, knob::bingo_debug_level),
   accumulation_table(knob::bingo_at_size, knob::bingo_pattern_len, knob::bingo_debug_level),
   pht(knob::bingo_pht_size, knob::bingo_pattern_len, knob::bingo_min_addr_width, knob::bingo_max_addr_width, knob::bingo_pc_width, knob::bingo_debug_level, knob::bingo_pht_ways),
   pf_streamer(knob::bingo_pf_streamer_size, knob::bingo_pattern_len, knob::bingo_debug_level), debug_level(knob::bingo_debug_level), 
   PERC(knob::bingo_min_addr_width, knob::bingo_max_addr_width, knob::bingo_pc_width, knob::bingo_pht_size, knob::bingo_pht_ways, pht.get_index_len(), knob::bingo_pattern_len),
   pf_filter() {
      init_knobs();
      init_stats();
      if(!knob::bingo_pc_address_fill_level.compare("L1"))
         pc_address_fill_level = FILL_L1;
      else if(!knob::bingo_pc_address_fill_level.compare("L2"))
         pc_address_fill_level = FILL_L2;
      else if(!knob::bingo_pc_address_fill_level.compare("LLC"))
         pc_address_fill_level = FILL_LLC;
   pf_filter.hist = &pht;
   pf_filter.perc = &PERC;


      
}

Bingo_PPF::~Bingo_PPF() {

}

void Bingo_PPF::print_config() { //TODO: cout
  //  cout << "bingo_region_size " << knob::bingo_region_size << endl
  //  << "bingo_pattern_len " << knob::bingo_pattern_len << endl
  //  << "bingo_pc_width " << knob::bingo_pc_width << endl
  //  << "bingo_min_addr_width " << knob::bingo_min_addr_width << endl
  //  << "bingo_max_addr_width " << knob::bingo_max_addr_width << endl
  //  << "bingo_ft_size " << knob::bingo_ft_size << endl
  //  << "bingo_at_size " << knob::bingo_at_size << endl
  //  << "bingo_pht_size " << knob::bingo_pht_size << endl
  //  << "bingo_pht_ways " << knob::bingo_pht_ways << endl
  //  << "bingo_pf_streamer_size " << knob::bingo_pf_streamer_size << endl
  //  << "bingo_debug_level " << knob::bingo_debug_level << endl
  //  << "bingo_l1d_thresh " << knob::bingo_l1d_thresh << endl
  //  << "bingo_l2c_thresh " << knob::bingo_l2c_thresh << endl
  //  << "bingo_llc_thresh " << knob::bingo_llc_thresh << endl
  //  << "bingo_pc_address_fill_level " << knob::bingo_pc_address_fill_level << endl
  //  << endl;
}

/**
* Updates BINGO's state based on the most recent LOAD access.
* @param block_number The block address of the most recent LOAD access
* @param pc           The PC of the most recent LOAD access
*/
void Bingo_PPF::access(uint64_t block_number, uint64_t pc) {
   if (this->debug_level >= 2)
   cerr << "[Bingo] access(block_number=0x" << hex << block_number << ", pc=0x" << pc << ")" << dec << endl;
   uint64_t region_number = block_number / this->pattern_len;
   int region_offset = block_number % this->pattern_len;
   bool success = this->accumulation_table.set_pattern(region_number, region_offset);
   if (success)
   return;
   FilterTable::Entry *entry = this->filter_table.find(region_number);
   if (!entry) {
      /* trigger access */
      this->filter_table.insert(region_number, pc, region_offset);
      vector<int> pattern = this->find_in_pht(pc, block_number);
      if (pattern.empty()) {
         /* nothing to prefetch */
         return;
      }
      /* give pattern to `pf_streamer` */
      // assert((int)pattern.size() == this->pattern_len);
      this->pf_streamer.insert(region_number, pattern);
      return;
   }
   if (entry->data.offset != region_offset) {
      /* move from filter table to accumulation table */
      uint64_t region_number = hash_index(entry->key, this->filter_table.get_index_len());
      AccumulationTable::Entry victim =
      this->accumulation_table.insert(region_number, entry->data.pc, entry->data.offset);
      this->accumulation_table.set_pattern(region_number, region_offset);
      this->filter_table.erase(region_number);
      if (victim.valid) {
         /* move from accumulation table to PHT */
         this->insert_in_pht(victim);
      }
   }
}

void Bingo_PPF::eviction(uint64_t block_number) {
   if (this->debug_level >= 2)
      cerr << "[Bingo] eviction(block_number=" << block_number << ")" << dec << endl;
   /* end of generation: footprint must now be stored in PHT */
   uint64_t region_number = block_number / this->pattern_len;
   this->filter_table.erase(region_number);
   AccumulationTable::Entry *entry = this->accumulation_table.erase(region_number);
   if (entry) {
      /* move from accumulation table to PHT */
      this->insert_in_pht(*entry);
   }
}

int Bingo_PPF::prefetch(uint64_t block_number) {
   int pf_issued = this->pf_streamer.prefetch(parent, block_number);
   if (this->debug_level >= 2)
      cerr << "[Bingo::prefetch] pf_issued=" << pf_issued << dec << endl;
   return pf_issued;
}

void Bingo_PPF::set_debug_level(int debug_level) {
   this->filter_table.set_debug_level(debug_level);
   this->accumulation_table.set_debug_level(debug_level);
   this->pht.set_debug_level(debug_level);
   this->pf_streamer.set_debug_level(debug_level);
   this->debug_level = debug_level;
}

void Bingo_PPF::log() {
   cerr << "Filter Table:" << dec << endl;
   cerr << this->filter_table.log();

   cerr << "Accumulation Table:" << dec << endl;
   cerr << this->accumulation_table.log();

   cerr << "Pattern History Table:" << dec << endl;
   cerr << this->pht.log();

   cerr << "Prefetch Streamer:" << dec << endl;
   cerr << this->pf_streamer.log();
}

/*========== stats ==========*/
/* NOTE: the BINGO code submitted for DPC3 (this code) does not call any of these methods. */

Event Bingo_PPF::get_event(uint64_t block_number) {
   uint64_t region_number = block_number / this->pattern_len;
   // assert(this->pht_events.count(region_number) == 1);
   return this->pht_events[region_number];
}

void Bingo_PPF::add_prefetch(uint64_t block_number) {
   Event ev = this->get_event(block_number);
   // assert(ev != MISS);
   this->prefetch_cnt[ev] += 1;
}

void Bingo_PPF::add_useful(uint64_t block_number, Event ev) {
   // assert(ev != MISS);
   this->useful_cnt[ev] += 1;
}

void Bingo_PPF::add_useless(uint64_t block_number, Event ev) {
   // assert(ev != MISS);
   this->useless_cnt[ev] += 1;
}

void Bingo_PPF::reset_stats() {
   this->pht_access_cnt = 0;
   this->pht_pc_address_cnt = 0;
   this->pht_pc_offset_cnt = 0;
   this->pht_miss_cnt = 0;

   for (int i = 0; i < 2; i += 1) {
      this->prefetch_cnt[i] = 0;
      this->useful_cnt[i] = 0;
      this->useless_cnt[i] = 0;
   }

   this->pref_level_cnt.clear();
   this->region_pref_cnt = 0;

   this->voter_sum = 0;
   this->vote_cnt = 0;
}

void Bingo_PPF::print_stats() {
  //  cout << "[Bingo] PHT Access: " << this->pht_access_cnt << endl;
  //  cout << "[Bingo] PHT Hit PC+Addr: " << this->pht_pc_address_cnt << endl;
  //  cout << "[Bingo] PHT Hit PC+Offs: " << this->pht_pc_offset_cnt << endl;
  //  cout << "[Bingo] PHT Miss: " << this->pht_miss_cnt << endl;

  //  cout << "[Bingo] Prefetch PC+Addr: " << this->prefetch_cnt[PC_ADDRESS] << endl;
  //  cout << "[Bingo] Prefetch PC+Offs: " << this->prefetch_cnt[PC_OFFSET] << endl;

  //  cout << "[Bingo] Useful PC+Addr: " << this->useful_cnt[PC_ADDRESS] << endl;
  //  cout << "[Bingo] Useful PC+Offs: " << this->useful_cnt[PC_OFFSET] << endl;

  //  cout << "[Bingo] Useless PC+Addr: " << this->useless_cnt[PC_ADDRESS] << endl;
  //  cout << "[Bingo] Useless PC+Offs: " << this->useless_cnt[PC_OFFSET] << endl;

  //  double l1_pref_per_region = 1.0 * this->pref_level_cnt[FILL_L1] / this->region_pref_cnt;
  //  double l2_pref_per_region = 1.0 * this->pref_level_cnt[FILL_L2] / this->region_pref_cnt;
  //  double l3_pref_per_region = 1.0 * this->pref_level_cnt[FILL_LLC] / this->region_pref_cnt;
  //  double no_pref_per_region = (double)this->pattern_len - (l1_pref_per_region + l2_pref_per_region + l3_pref_per_region);

  //  cout << "[Bingo] L1 Prefetch per Region: " << l1_pref_per_region << endl;
  //  cout << "[Bingo] L2 Prefetch per Region: " << l2_pref_per_region << endl;
  //  cout << "[Bingo] L3 Prefetch per Region: " << l3_pref_per_region << endl;
  //  cout << "[Bingo] No Prefetch per Region: " << no_pref_per_region << endl;

  //  double voter_mean = 1.0 * this->voter_sum / this->vote_cnt;
  //  double voter_sqr_mean = 1.0 * this->voter_sqr_sum / this->vote_cnt;
  //  double voter_sd = sqrt(voter_sqr_mean - square(voter_mean));
  //  cout << "[Bingo] Number of Voters Mean: " << voter_mean << endl;
  //  cout << "[Bingo] Number of Voters SD: " << voter_sd << endl;
  //  cout << endl;
}

/**
* Performs a PHT lookup and computes a prefetching pattern from the result.
* @return The appropriate prefetch level for all blocks based on PHT output or an empty vector
*         if no blocks should be prefetched
*/
vector<int> Bingo_PPF::find_in_pht(uint64_t pc, uint64_t address) {
   if (this->debug_level >= 2) {
      cerr << "[Bingo] find_in_pht(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
   }
   uint64_t key = this->pht.get_key(pc, address);
   uint64_t index = key % (this->pht.get_num_sets());

   vector<vector<bool>> matches = this->pht.find(pc, address);
   this->pht_access_cnt += 1;
   Event pht_last_event = this->pht.get_last_event();
   uint64_t region_number = address / this->pattern_len;
   if (pht_last_event != MISS)
   this->pht_events[region_number] = pht_last_event;
   vector<int> pattern;
   if (pht_last_event == PC_ADDRESS) {
      this->pht_pc_address_cnt += 1;
      // assert(matches.size() == 1); /* there can only be 1 PC+Address match */
      // assert(matches[0].size() == (unsigned)this->pattern_len);
      pattern.resize(this->pattern_len, 0);
      for (int i = 0; i < this->pattern_len; i += 1)
      if (matches[0][i])
         pattern[i] = pc_address_fill_level;
   } else if (pht_last_event == PC_OFFSET) {
      this->pht_pc_offset_cnt += 1;
      // pattern = this->vote(matches);
      vector<vector<int>> counts = count_votes(matches, index);
      for (int i = 0; i < this->pattern_len; i+=1) {
         int32_t perc_sum = PERC.perc_predict(address, pht.ip_0, pht.ip_1, pht.ip_2, pht.ip_3, counts[1][i], counts[0][i]); //recency, votes
         // TODO: determine prefetch level
         bool do_pf = (perc_sum >= knob::ppf_perc_threshold_lo) ? 1 : 0;
         bool fill_l2 = (perc_sum >= knob::ppf_perc_threshold_hi) ? 1 : 0;

         pattern[i] = fill_l2 ? BINGO_L2C_PREFETCH : do_pf ? BINGO_LLC_PREFETCH : 0; 
         

         // Recording Perc negatives (perceptron didn't prefetch)
         if (perc_sum < knob::ppf_perc_threshold_hi) {
				// Note: Using knob::ppf_perc_threshold_hi as the decising factor for negative case
				// Because 'trueness' of a prefetch is decisded based on the feedback from L2C
				// So even though LLC prefetches go through, they are treated as false wrt L2C in this case
            uint64_t pf_addr = address & ~(PAGE_SIZE - 1) + (i << LOG2_BLOCK_SIZE);
            
            filter->check(pf_addr, address, pc, BINGO_PERC_REJECT, train_delta + delta[set][way], last_sig, curr_sig, pf_conf, perc_sum, depth);

             

         }

    
      }
   } else if (pht_last_event == MISS) {
      this->pht_miss_cnt += 1;
   } else {
      /* error: unknown event! */
      // assert(0);
   }
   /* stats */
   if (pht_last_event != MISS) {
      this->region_pref_cnt += 1;
      for (int i = 0; i < (int)pattern.size(); i += 1)
      if (pattern[i] != 0)
      this->pref_level_cnt[pattern[i]] += 1;
      // assert(this->pref_level_cnt.size() <= 3); /* L1, L2, L3 */
   }
   /* ===== */
   return pattern;
}

void Bingo_PPF::insert_in_pht(const AccumulationTable::Entry &entry) {
   uint64_t pc = entry.data.pc;
   uint64_t region_number = hash_index(entry.key, this->accumulation_table.get_index_len());
   uint64_t address = region_number * this->pattern_len + entry.data.offset;
   if (this->debug_level >= 2) {
      cerr << "[Bingo] insert_in_pht(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
   }
   const vector<bool> &pattern = entry.data.pattern;
   this->pht.insert(pc, address, pattern);
}

/**
* Uses a voting mechanism to produce a prefetching pattern from a set of footprints.
* @param x The patterns obtained from all PC+Offset matches
* @return  The appropriate prefetch level for all blocks based on BINGO's voting thresholds or
*          an empty vector if no blocks should be prefetched
*/
// vector<int> Bingo_PPF::vote(const vector<vector<bool>> &x) {
//    if (this->debug_level >= 2)
//    cerr << "Bingo::vote(...)" << endl;
//    int n = x.size();
//    if (n == 0) {
//       if (this->debug_level >= 2)
//       cerr << "[Bingo::vote] There are no voters." << endl;
//       return vector<int>();
//    }
//    /* stats */
//    this->vote_cnt += 1;
//    this->voter_sum += n;
//    this->voter_sqr_sum += square(n);
//    /* ===== */
//    if (this->debug_level >= 2) {
//       cerr << "[Bingo::vote] Taking a vote among:" << endl;
//       for (int i = 0; i < n; i += 1)
//       cerr << "<" << setw(3) << i + 1 << "> " << pattern_to_string(x[i]) << endl;
//    }
//    bool pf_flag = false;
//    vector<int> res(this->pattern_len, 0);
//    for (int i = 0; i < n; i += 1)
//    // assert((int)x[i].size() == this->pattern_len);
//    for (int i = 0; i < this->pattern_len; i += 1) {
//       int cnt = 0;
//       for (int j = 0; j < n; j += 1)
//       if (x[j][i])
//       cnt += 1;
//       // TODO: make vector of p pattern_len long, each prefetch has an associated vote count.
//       double p = 1.0 * cnt / n;
//       if (p >= knob::bingo_l1d_thresh)
//          res[i] = FILL_L1;
//       else if (p >= knob::bingo_l2c_thresh)
//          res[i] = FILL_L2;
//       else if (p >= knob::bingo_llc_thresh)
//          res[i] = FILL_LLC;
//       else
//          res[i] = 0;
//       if (res[i] != 0)
//          pf_flag = true;
//    }
//    if (this->debug_level >= 2) {
//       cerr << "<res> " << pattern_to_string(res) << endl;
//    }
//    if (!pf_flag)
//    return vector<int>();
//    return res;
// }


// FIXME: first row is vote counts, second row is average recency of votes.
   vector<vector<int>> Bingo_PPF::count_votes(const vector<vector<bool>> &x, uint64_t index) {
   if (this->debug_level >= 2)
   cerr << "Bingo::count_votes(...)" << endl;
   int n = x.size();
   if (n == 0) {
      if (this->debug_level >= 2)
      cerr << "[Bingo::vote] There are no voters." << endl;
      return vector<vector<int>>();
   }
   /* stats */
   this->vote_cnt += 1;
   this->voter_sum += n;
   this->voter_sqr_sum += square(n);
   /* ===== */
   if (this->debug_level >= 2) {
      cerr << "[Bingo::vote] Taking a vote among:" << endl;
      for (int i = 0; i < n; i += 1)
      cerr << "<" << setw(3) << i + 1 << "> " << pattern_to_string(x[i]) << endl;
   }

   // bool pf_flag = false;
   
   // FIXME: first row is vote counts, second row is average recency of votes.
   // Convert the LRU recencies to fall into [0, pht_ways-1]
   vector<vector<int>> res(2, std::vector<int>(this->pattern_len, 0));
   vector<uint64_t> LRU_idxs = this->pht.LRU_argsort(index);

   for (int i = 0; i < n; i += 1)
   // assert((int)x[i].size() == this->pattern_len);
   // look at each cache block
   for (int i = 0; i < this->pattern_len; i += 1) {
      // sum votes and recencies across each offset match
      for (int j = 0; j < n; j += 1) {
         if (x[j][i]) {
            res[0][i] += 1; // another vote for this block
            res[1][i] += LRU_idxs[this->pht.way_matches[j]]; // add LRU for this vote
         }
         
      }
      // Get average recency by dividing recency total by vote count
      if (res[1][i] > 0) {
         res[1][i] /= res[0][i];
      }
   }
   if (this->debug_level >= 2) {
      cerr << "<votes> " << pattern_to_string(res[0]) << endl;
      cerr << "<recencies> " << pattern_to_string(res[1]) << endl;
   }
   // if (!pf_flag)
   //    return vector<vector<int>>();
   return res;
}




/* Base-class virtual function */
void Bingo_PPF::invoke_prefetcher(uint64_t pc, uint64_t addr, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr)
{
   if (debug_level >= 2) {
      cerr << "CACHE::l1d_prefetcher_operate(addr=0x" << hex << addr << ", PC=0x" << pc << ", cache_hit=" << dec
      << (int)cache_hit << ", type=" << (int)type << ")" << dec << endl;
   }

   if (type != LOAD)
   return;

   uint64_t block_number = addr >> LOG2_BLOCK_SIZE;

   /* update BINGO with most recent LOAD access */
   access(block_number, pc);

   /* issue prefetches */
   prefetch(block_number);

   if (debug_level >= 3) {
      log();
      cerr << "=======================================" << dec << endl;
   }
}

void Bingo_PPF::register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr) {
   uint64_t evicted_block_number = evicted_addr >> LOG2_BLOCK_SIZE;

   if (parent->block[set][way].valid == 0)
   return; /* no eviction */

   /* inform all sms modules of the eviction */
   /* RBERA: original code was to send eviction signal to Bingo in every core
   * modified it to make the signal local */
   eviction(evicted_block_number);
}

void Bingo_PPF::dump_stats() {
   print_stats();
}

///////////////////////////////////////////////////// PERCEPTRON FUNCTIONS ///////////////////////////////////////////


 
void PERCEPTRON::get_perc_index(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count, uint64_t perc_set[PERC_FEATURES])
{
   
 // Returns the indexes for the perceptron tables
   uint64_t cache_line = base_addr, // In BINGO, memory address is block number
      page_addr  = base_addr / this->pattern_len;

   uint64_t pc = ip & (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc */
   uint64_t pc_1 = ip_1 & (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc_1 */
   uint64_t pc_2 = ip_2 & (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc_2 */
   uint64_t pc_3 = ip_3 & (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc_3 */

   uint64_t address = base_addr & (1 << this->max_addr_width) - 1; /* use `addr_width` bits from address */
   uint64_t offset = address & ((1 << this->min_addr_width) - 1);

   uint64_t address_hash = hash_index((pc << this->max_addr_width) | address, 12); // 4096 entries
   uint64_t offset_hash = hash_index((pc << this->min_addr_width) | offset, 12); // 4096 entries


 uint64_t  pre_hash[PERC_FEATURES];

  //FIXME: features prior to index hash
 pre_hash[0] = address;
 pre_hash[1] = vote_count;
 pre_hash[2] = page_addr;
 pre_hash[3] = address_hash; // "PC+Address" 
 pre_hash[4] = offset_hash; // "PC+Offset"
 pre_hash[5] = pc_1 ^ (pc_2>>1) ^ (pc_3>>2);
 pre_hash[6] = avg_recency; // Average Recency 
//  pre_hash[7] = vote_count; // Vote Count

 for (int i = 0; i < PERC_FEATURES; i++) {
   perc_set[i] = (pre_hash[i]) % PERC_DEPTH[i]; // Variable depths
   // SPP_DP (
   //   cout << "  Perceptron Set Index#: " << i << " = " <<  perc_set[i];
   // );
 }
//  SPP_DP (
   // cout << endl;
//  );		
}

int32_t	PERCEPTRON::perc_predict(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count)
{
//  SPP_DP (
//    int sig_delta = (cur_delta < 0) ? (((-1) * cur_delta) + (1 << (SIG_DELTA_BIT - 1))) : cur_delta;
//    cout << "[PERC_PRED] Current IP: " << ip << "  and  Memory Adress: " << hex << base_addr << endl;
//    cout << " Last Sig: " << last_sig << " Curr Sig: " << curr_sig << dec << endl;
//    cout << " Cur Delta: " << cur_delta << " Sign Delta: " << sig_delta << " Confidence: " << confidence<< endl;
//    cout << " ";
//  );

 uint64_t perc_set[PERC_FEATURES];
 // Get the indexes in perc_set[]
 get_perc_index(base_addr, ip, ip_1, ip_2, ip_3, avg_recency, vote_count, perc_set);
 
 int32_t sum = 0;
 for (int i = 0; i < PERC_FEATURES; i++) {
   sum += perc_weights[perc_set[i]][i];	
   // Calculate Sum
 }
//  SPP_DP (
//    cout << " Sum of perceptrons: " << sum << " Prediction made: " << ((sum >= knob::ppf_perc_threshold_lo) ?  ((sum >= knob::ppf_perc_threshold_hi) ? FILL_L2 : FILL_LLC) : 0)  << endl;
//  );
 // Return the sum
 return sum;
}

void 	PERCEPTRON::perc_update(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count, bool direction, int32_t perc_sum)
{
//  SPP_DP (
//    int sig_delta = (cur_delta < 0) ? (((-1) * cur_delta) + (1 << (SIG_DELTA_BIT - 1))) : cur_delta;
//    cout << "[PERC_UPD] (Recorded) IP: " << ip << "  and  Memory Adress: " << hex << base_addr << endl;
//    cout << " Last Sig: " << last_sig << " Curr Sig: " << curr_sig << dec << endl;
//    cout << " Cur Delta: " << cur_delta << " Sign Delta: " << sig_delta << " Confidence: "<< confidence << " Update Direction: " << direction << endl;
//    cout << " ";
//  );

 uint64_t perc_set[PERC_FEATURES];
 // Get the perceptron indexes
 get_perc_index(base_addr, ip, ip_1, ip_2, ip_3, avg_recency, vote_count, perc_set);
 
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
   // SPP_DP (
   //   int differential = (sum >= knob::ppf_perc_threshold_hi) ? -1 : 1;
   //   cout << " Direction is: " << direction << " and sum is:" << sum;
   //   cout << " Overall Differential: " << differential << endl;
   // );
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
   // SPP_DP (
   //   int differential = 0;
   //   if (sum >= knob::ppf_perc_threshold_hi) differential =  1;
   //   if (sum  < knob::ppf_perc_threshold_hi) differential = -1;
   //   cout << " Direction is: " << direction << " and sum is:" << sum;
   //   cout << " Overall Differential: " << differential << endl;
   // );
 }
}

////////////////////////////////////////////////// PREFETCH FILTER start Prefetch_filter start////////////////////////////////
bool PREFETCH_FILTER::check(uint64_t check_addr, uint64_t base_addr, uint64_t ip, FILTER_REQUEST filter_request, uint64_t avg_recency, uint64_t vote_count, bool direction, int32_t perc_sum) {
      uint64_t cache_line = check_addr >> LOG2_BLOCK_SIZE,
               hash = spp_ppf::get_hash(cache_line);
   
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
      
      case SPP_PERC_REJECT: // To see what would have been the prediction given perceptron has rejected the PF
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
            delta_reject[quotient_reject] = cur_delta;
            perc_sum_reject[quotient_reject] = sum;
            last_signature_reject[quotient_reject] = last_sig;
            cur_signature_reject[quotient_reject] = curr_sig;
            confidence_reject[quotient_reject] = conf;
            la_depth_reject[quotient_reject] = depth;

            SPP_DP (
                     cout << "[FILTER] " << __func__ << " PF rejected by perceptron. Set valid_reject for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                     cout << " quotient: " << quotient << " remainder_tag: " << remainder_tag_reject[quotient_reject] << endl; 
               cout << " More Recorded Metadata: Addr: " << hex << address_reject[quotient_reject] << dec << " PC: " << pc_reject[quotient_reject] << " Delta: " << delta_reject[quotient_reject] << " Last Signature: " << last_signature_reject[quotient_reject] << " Current Signature: " << cur_signature_reject[quotient_reject] << " Confidence: " << confidence_reject[quotient_reject] << endl;
                  );
         }
         break;
      
      case SPP_L2C_PREFETCH:
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
            delta[quotient] = cur_delta;
            pc[quotient] = ip;
            pc_1[quotient] = ghr->ip_1;
            pc_2[quotient] = ghr->ip_2;
            pc_3[quotient] = ghr->ip_3;
            last_signature[quotient] = last_sig; 
            cur_signature[quotient] = curr_sig;
            confidence[quotient] = conf;
            address[quotient] = base_addr; 
            perc_sum[quotient] = sum;
            la_depth[quotient] = depth;
            
            SPP_DP (
                     cout << "[FILTER] " << __func__ << " set valid for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                     cout << " quotient: " << quotient << " remainder_tag: " << remainder_tag[quotient] << " valid: " << valid[quotient] << " useful: " << useful[quotient] << endl; 
               cout << " More Recorded Metadata: Addr:" << hex << address[quotient] << dec << " PC: " << pc[quotient] << " Delta: " << delta[quotient] << " Last Signature: " << last_signature[quotient] << " Current Signature: " << cur_signature[quotient] << " Confidence: " << confidence[quotient] << endl;
                  );
            }
            break;

         case SPP_LLC_PREFETCH:
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
               perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], delta[quotient], last_signature[quotient], cur_signature[quotient], confidence[quotient], la_depth[quotient], 1, perc_sum[quotient]);
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
               perc->perc_update(address_reject[quotient_reject], pc_reject[quotient_reject], pc_1_reject[quotient_reject], pc_2_reject[quotient_reject], pc_3_reject[quotient_reject], delta_reject[quotient_reject], last_signature_reject[quotient_reject], cur_signature_reject[quotient_reject], confidence_reject[quotient_reject], la_depth_reject[quotient_reject], 0, perc_sum_reject[quotient_reject]);
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
            perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], delta[quotient], last_signature[quotient], cur_signature[quotient], confidence[quotient], la_depth[quotient], 0, perc_sum[quotient]);
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




////////////////////////////////////////////////// PREFETCH FILTER end Prefetch_filter end////////////////////////////////

/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 
/////////////////////////////////////////////// PPF MODifications START ////////////////////////////////////////////////// 
/*

namespace ppf_mods{


//FIXME: Changes to filter::check(), the function that checks the filter, recording useful prefetches.

{
    //MAIN FILTER
 uint64_t quotient = (hash >> REMAINDER_BIT) & ((1 << QUOTIENT_BIT) - 1),
            remainder = hash % (1 << REMAINDER_BIT);
 
 //REJECT FILTER
 uint64_t quotient_reject = (hash >> REMAINDER_BIT_REJ) & ((1 << QUOTIENT_BIT_REJ) - 1),
            remainder_reject = hash % (1 << REMAINDER_BIT_REJ);

  // FIXME: inside switch statement if it's a rejected prefetch

     case SPP_PERC_REJECT: // To see what would have been the prediction given perceptron has rejected the PF
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
        delta_reject[quotient_reject] = cur_delta;
        perc_sum_reject[quotient_reject] = sum;
        last_signature_reject[quotient_reject] = last_sig;
        cur_signature_reject[quotient_reject] = curr_sig;
        confidence_reject[quotient_reject] = conf;
        la_depth_reject[quotient_reject] = depth;

        SPP_DP (
                 cout << "[FILTER] " << __func__ << " PF rejected by perceptron. Set valid_reject for check_addr: " << hex << check_addr << " cache_line: " << cache_line << dec;
                 cout << " quotient: " << quotient << " remainder_tag: " << remainder_tag_reject[quotient_reject] << endl; 
           cout << " More Recorded Metadata: Addr: " << hex << address_reject[quotient_reject] << dec << " PC: " << pc_reject[quotient_reject] << " Delta: " << delta_reject[quotient_reject] << " Last Signature: " << last_signature_reject[quotient_reject] << " Current Signature: " << cur_signature_reject[quotient_reject] << " Confidence: " << confidence_reject[quotient_reject] << endl;
              );
     }
     break;

  // FIXME: inside switch statement if it's a demand access
     case SPP_L2C_PREFETCH:
     // FIXME: else block, adding new entry to filter
       // Logging perc features
       delta[quotient] = cur_delta;
       pc[quotient] = ip;
       pc_1[quotient] = ghr->ip_1;
       pc_2[quotient] = ghr->ip_2;
       pc_3[quotient] = ghr->ip_3;
       last_signature[quotient] = last_sig; 
       cur_signature[quotient] = curr_sig;
       confidence[quotient] = conf;
       address[quotient] = base_addr; 
       perc_sum[quotient] = sum;
       la_depth[quotient] = depth;


  // FIXME: inside switch statement if it's a demand access
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
           perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], delta[quotient], last_signature[quotient], cur_signature[quotient], confidence[quotient], la_depth[quotient], 1, perc_sum[quotient]);
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
           perc->perc_update(address_reject[quotient_reject], pc_reject[quotient_reject], pc_1_reject[quotient_reject], pc_2_reject[quotient_reject], pc_3_reject[quotient_reject], delta_reject[quotient_reject], last_signature_reject[quotient_reject], cur_signature_reject[quotient_reject], confidence_reject[quotient_reject], la_depth_reject[quotient_reject], 0, perc_sum_reject[quotient_reject]);
           valid_reject[quotient_reject] = 0;
           remainder_tag_reject[quotient_reject] = 0;
        }
     }
        break;


  // FIXME: inside switch statement if it's an eviction
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
        perc->perc_update(address[quotient], pc[quotient], pc_1[quotient], pc_2[quotient], pc_3[quotient], delta[quotient], last_signature[quotient], cur_signature[quotient], confidence[quotient], la_depth[quotient], 0, perc_sum[quotient]);
     }
        // Reset filter entry
        valid[quotient] = 0;
        useful[quotient] = 0;
        remainder_tag[quotient] = 0;

     // Reset reject filter too
     valid_reject[quotient_reject] = 0;
     remainder_tag_reject[quotient_reject] = 0;

        break;

}


//////////////////////////////////////////////////////FIXME: PERCEPTRON FUNCTIONS START
//////////////////////////////////////////////////////FIXME: PERCEPTRON FUNCTIONS END


// FIXME: invoke_prefetcher modifications:

{
  confidence_q[100*L2C_MSHR_SIZE],

  int32_t  delta = 0,
     delta_q[100*L2C_MSHR_SIZE],
     perc_sum_q[100*L2C_MSHR_SIZE];

     for (uint32_t i = 0; i < 100*L2C_MSHR_SIZE; i++){
        confidence_q[i] = 0;
        delta_q[i] = 0;
        perc_sum_q[i] = 0;
    }

  //  FIXME: tracking last PAGES_TRACKED pages for each invocation
    for (int i = PAGES_TRACKED-1; i>0; i--) { // N down to 1
     GHR.page_tracker[i] = GHR.page_tracker[i-1];
 }
 GHR.page_tracker[0] = page;

 int distinct_pages = 0;
 uint8_t num_pf = 0;
 for (int i=0; i < PAGES_TRACKED; i++) {
     int j;
     for (j=0; j<i; j++) {
         if (GHR.page_tracker[i] == GHR.page_tracker[j])
             break;
     }
     if (i==j)
         distinct_pages++;
 }
 //cout << "Distinct Pages: " << distinct_pages << endl;

   // Stage 1: Read and update a sig stored in ST
   // last_sig and delta are used to update (sig, delta) correlation in PT
   // curr_sig is used to read prefetch candidates in PT 
   ST.read_and_update_sig(page, page_offset, last_sig, curr_sig, delta);
   
   // Also check the prefetch filter in parallel to update global accuracy counters 
   FILTER.check(addr, 0, 0, L2C_DEMAND, 0, 0, 0, 0, 0, 0); 
 

   // Stage 3: Start prefetching
   uint64_t base_addr = addr;
   uint64_t curr_ip = ip;
   uint32_t lookahead_conf = 100,
            pf_q_head = 0, 
            pf_q_tail = 0;
   uint8_t  do_lookahead = 0;
   int32_t  prev_delta = 0;

   uint64_t train_addr  = addr;
   int32_t  train_delta = 0;
  // FIXME: remembering last few instruction pointers for  PPF feature: PC1 XOR PC2»1 XOR PC3»2
   GHR.ip_3 = GHR.ip_2;
   GHR.ip_2 = GHR.ip_1;
   GHR.ip_1 = GHR.ip_0;
   GHR.ip_0 = ip;


  // FIXME: in lookahead do while loop
   train_addr  = addr; train_delta = prev_delta;
   // Remembering the original addr here and accumulating the deltas in lookahead stages
   
   // Read the PT. Also passing info required for perceptron inferencing as PT calls perc_predict()
   PT.read_pattern(curr_sig, delta_q, confidence_q, perc_sum_q, lookahead_way, lookahead_conf, pf_q_tail, depth, addr, base_addr, train_addr, curr_ip, train_delta, last_sig, m_parent_cache->PQ.occupancy, m_parent_cache->PQ.SIZE, m_parent_cache->MSHR.occupancy, m_parent_cache->MSHR.SIZE);

  // FIXME: queues populated. now loop through them
     for (uint32_t i = pf_q_head; i < pf_q_tail; i++) {

        uint64_t pf_addr = (base_addr & ~(BLOCK_SIZE - 1)) + (delta_q[i] << LOG2_BLOCK_SIZE);
        int32_t perc_sum   = perc_sum_q[i];

        SPP_DP(
           cout << "[ChampSim] State of features: \nTrain addr: " << train_addr << "\tCurr IP: " << curr_ip << "\tIP_1: " << GHR.ip_1 << "\tIP_2: " << GHR.ip_2 << "\tIP_3: " << GHR.ip_3 << "\tDelta: " << train_delta + delta_q[i] << "\t:LastSig " << last_sig << "\t:CurrSig " << curr_sig << "\t:Conf " << confidence_q[i] << "\t:Depth " << depth << "\tSUM: "<< perc_sum  << endl;
        );
        FILTER_REQUEST fill_level = (perc_sum >= knob::ppf_perc_threshold_hi) ? SPP_L2C_PREFETCH : SPP_LLC_PREFETCH;
        
        if ((addr & ~(PAGE_SIZE - 1)) == (pf_addr & ~(PAGE_SIZE - 1))) { // Prefetch request is in the same physical page
           
           // Filter checks for redundancy and returns FALSE if redundant
           // Else it returns TRUE and logs the features for future retrieval 
           // FIXME: evenly distributes prefetches across distinct pages
           if ( num_pf < ceil(((m_parent_cache->PQ.SIZE)/distinct_pages)) ) {              
              if (FILTER.check(pf_addr, train_addr, curr_ip, fill_level, train_delta + delta_q[i], last_sig, curr_sig, confidence_q[i], perc_sum, (depth-1))) {

                    //[DO NOT TOUCH]:   
                    // Use addr (not base_addr) to obey the same physical page boundary
                    m_parent_cache->prefetch_line(ip, addr, pf_addr, ((fill_level == SPP_L2C_PREFETCH) ? FILL_L2 : FILL_LLC),5); 
                    num_pf++;
                    
                    //FILTER.valid_reject[quotient] = 0;
                    if (fill_level == SPP_L2C_PREFETCH) {
                       GHR.pf_issued++;
                       if (GHR.pf_issued > GLOBAL_COUNTER_MAX) {
                          GHR.pf_issued >>= 1;
                          GHR.pf_useful >>= 1;
                       }
                       SPP_DP (cout << "[ChampSim] SPP L2 prefetch issued GHR.pf_issued: " << GHR.pf_issued << " GHR.pf_useful: " << GHR.pf_useful << endl;);
                    }

                    SPP_DP (
                       cout << "[ChampSim] " << __func__ << " base_addr: " << hex << base_addr << " pf_addr: " << pf_addr;
                       cout << " pf_cache_line: " << (pf_addr >> LOG2_BLOCK_SIZE);
                       cout << " prefetch_delta: " << dec << delta_q[i] << " confidence: " << confidence_q[i];
                       cout << " depth: " << i << " fill_level: " << ((fill_level == SPP_L2C_PREFETCH) ? FILL_L2 : FILL_LLC) << endl;
                    );
              }
           }   
        } else { // Prefetch request is crossing the physical page boundary
  #ifdef GHR_ON
              // Store this prefetch request in GHR to bootstrap SPP learning when we see a ST miss (i.e., accessing a new page)
              GHR.update_entry(curr_sig, confidence_q[i], (pf_addr >> LOG2_BLOCK_SIZE) & 0x3F, delta_q[i]); 
  #endif
        }
        do_lookahead = 1;
        pf_q_head++;
  }

  // FIXME: WHen miss is filled in cache.
  void SPP_PPF_dev::cache_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr)
  {
  #ifdef FILTER_ON
      SPP_DP (cout << endl;);
      FILTER.check(evicted_addr, 0, 0, L2C_EVICT, 0, 0, 0, 0, 0, 0);
  #endif
  }
  

}



/////////////////////////////////////////////// ^^ PPF MODS END ^^  //////////////////////////////////////////////////
