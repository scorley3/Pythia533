#ifndef BINGO_PPF_H
#define BINGO_PPF_H


/* Bingo [https://mshakerinava.github.io/papers/bingo-hpca19.pdf] */

#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include "prefetcher.h"
#include "cache.h"
#include "bakshalipour_framework.h"

// FIXME: ppf includes:
#include <iostream>
#include <fstream>
#include <iomanip>      // std::setw
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <cmath>


using namespace std;


enum FILTER_REQUEST {BINGO_L2C_PREFETCH, BINGO_LLC_PREFETCH, L2C_DEMAND, L2C_EVICT, BINGO_PERC_REJECT}; // Request type for prefetch filter

// Prefetch filter parameters
#define QUOTIENT_BIT  10
#define REMAINDER_BIT 6
#define HASH_BIT (QUOTIENT_BIT + REMAINDER_BIT + 1)
#define FILTER_SET (1 << QUOTIENT_BIT)

#define QUOTIENT_BIT_REJ  10
#define REMAINDER_BIT_REJ 8
#define HASH_BIT_REJ (QUOTIENT_BIT_REJ + REMAINDER_BIT_REJ + 1)
#define FILTER_SET_REJ (1 << QUOTIENT_BIT_REJ)


// FIXME: Perceptron paramaters
#define PERC_ENTRIES 4096 //Upto 12-bit addressing in hashed perceptron
#define PERC_FEATURES 7 //Keep increasing based on new features
#define PERC_COUNTER_MAX 15 //-16 to +15: 5 bits counter 
// #define PERC_THRESHOLD_HI  -5
// #define PERC_THRESHOLD_LO  -15
#define POS_UPDT_THRESHOLD  90
#define NEG_UPDT_THRESHOLD -80


class FilterTableData {
   public:
      uint64_t pc;
      int offset;
   };
   
   class FilterTable : public LRUSetAssociativeCache<FilterTableData> {
      typedef LRUSetAssociativeCache<FilterTableData> Super;
   
   public:
      FilterTable(int size, int debug_level = 0, int num_ways = 16) : Super(size, num_ways, debug_level) {
         // assert(__builtin_popcount(size) == 1);
         if (this->debug_level >= 1)
         cerr << "FilterTable::FilterTable(size=" << size << ", debug_level=" << debug_level
         << ", num_ways=" << num_ways << ")" << dec << endl;
      }
   
      Entry *find(uint64_t region_number) {
         if (this->debug_level >= 2)
         cerr << "FilterTable::find(region_number=0x" << hex << region_number << ")" << dec << endl;
         uint64_t key = this->build_key(region_number);
         Entry *entry = Super::find(key);
         if (!entry) {
            if (this->debug_level >= 2)
            cerr << "[FilterTable::find] Miss!" << dec << endl;
            return nullptr;
         }
         if (this->debug_level >= 2)
         cerr << "[FilterTable::find] Hit!" << dec << endl;
         Super::set_mru(key);
         return entry;
      }
   
      void insert(uint64_t region_number, uint64_t pc, int offset) {
         if (this->debug_level >= 2)
         cerr << "FilterTable::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
         << ", offset=" << dec << offset << ")" << dec << endl;
         uint64_t key = this->build_key(region_number);
         // assert(!Super::find(key));
         Super::insert(key, {pc, offset});
         Super::set_mru(key);
      }
   
      Entry *erase(uint64_t region_number) {
         uint64_t key = this->build_key(region_number);
         return Super::erase(key);
      }
   
      string log() {
         vector<string> headers({"Region", "PC", "Offset"});
         return Super::log(headers);
      }
   
   private:
      /* @override */
      void write_data(Entry &entry, Table &table, int row) {
         uint64_t key = hash_index(entry.key, this->index_len);
         table.set_cell(row, 0, key);
         table.set_cell(row, 1, entry.data.pc);
         table.set_cell(row, 2, entry.data.offset);
      }
   
      uint64_t build_key(uint64_t region_number) {
         uint64_t key = region_number & ((1ULL << 37) - 1);
         return hash_index(key, this->index_len);
      }
   
      /*==========================================================*/
      /* Entry   = [tag, offset, PC, valid, LRU]                  */
      /* Storage = size * (37 - lg(sets) + 5 + 16 + 1 + lg(ways)) */
      /* 64 * (37 - lg(4) + 5 + 16 + 1 + lg(16)) = 488 Bytes      */
      /*==========================================================*/
   };
   
   template <class T> string pattern_to_string(const vector<T> &pattern) {
      ostringstream oss;
      for (unsigned i = 0; i < pattern.size(); i += 1)
      oss << int(pattern[i]);
      return oss.str();
   }
   
   class AccumulationTableData {
   public:
      uint64_t pc;
      int offset;
      vector<bool> pattern;
   };
   
   class AccumulationTable : public LRUSetAssociativeCache<AccumulationTableData> {
      typedef LRUSetAssociativeCache<AccumulationTableData> Super;
   
   public:
      AccumulationTable(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
      : Super(size, num_ways, debug_level), pattern_len(pattern_len) {
         // assert(__builtin_popcount(size) == 1);
         // assert(__builtin_popcount(pattern_len) == 1);
         if (this->debug_level >= 1)
         cerr << "AccumulationTable::AccumulationTable(size=" << size << ", pattern_len=" << pattern_len
         << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
      }
   
      /**
      * @return False if the tag wasn't found and true if the pattern bit was successfully set
      */
      bool set_pattern(uint64_t region_number, int offset) {
         if (this->debug_level >= 2)
         cerr << "AccumulationTable::set_pattern(region_number=0x" << hex << region_number << ", offset=" << dec
         << offset << ")" << dec << endl;
         uint64_t key = this->build_key(region_number);
         Entry *entry = Super::find(key);
         if (!entry) {
            if (this->debug_level >= 2)
            cerr << "[AccumulationTable::set_pattern] Not found!" << dec << endl;
            return false;
         }
         entry->data.pattern[offset] = true;
         Super::set_mru(key);
         if (this->debug_level >= 2)
         cerr << "[AccumulationTable::set_pattern] OK!" << dec << endl;
         return true;
      }
   
      /* NOTE: `region_number` is probably truncated since it comes from the filter table */
      Entry insert(uint64_t region_number, uint64_t pc, int offset) {
         if (this->debug_level >= 2)
         cerr << "AccumulationTable::insert(region_number=0x" << hex << region_number << ", pc=0x" << pc
         << ", offset=" << dec << offset << dec << endl;
         uint64_t key = this->build_key(region_number);
         // assert(!Super::find(key));
         vector<bool> pattern(this->pattern_len, false);
         pattern[offset] = true;
         Entry old_entry = Super::insert(key, {pc, offset, pattern});
         Super::set_mru(key);
         return old_entry;
      }
   
      Entry *erase(uint64_t region_number) {
         uint64_t key = this->build_key(region_number);
         return Super::erase(key);
      }
   
      string log() {
         vector<string> headers({"Region", "PC", "Offset", "Pattern"});
         return Super::log(headers);
      }
   
   private:
      /* @override */
      void write_data(Entry &entry, Table &table, int row) {
         uint64_t key = hash_index(entry.key, this->index_len);
         table.set_cell(row, 0, key);
         table.set_cell(row, 1, entry.data.pc);
         table.set_cell(row, 2, entry.data.offset);
         table.set_cell(row, 3, pattern_to_string(entry.data.pattern));
      }
   
      uint64_t build_key(uint64_t region_number) {
         uint64_t key = region_number & ((1ULL << 37) - 1);
         return hash_index(key, this->index_len);
      }
   
      int pattern_len;
   
      /*===============================================================*/
      /* Entry   = [tag, map, offset, PC, valid, LRU]                  */
      /* Storage = size * (37 - lg(sets) + 32 + 5 + 16 + 1 + lg(ways)) */
      /* 128 * (37 - lg(8) + 32 + 5 + 16 + 1 + lg(16)) = 1472 Bytes    */
      /*===============================================================*/
   };
   
   /**
   * There are 3 possible outcomes (here called `Event`) for a PHT lookup:
   * PC+Address hit, PC+Offset hit(s), or Miss.
   * NOTE: `Event` is only used for gathering stats.
   */
   enum Event { PC_ADDRESS = 0, PC_OFFSET = 1, MISS = 2 };
   
   template <class T> vector<T> my_rotate(const vector<T> &x, int n) {
      vector<T> y;
      int len = x.size();
      n = n % len;
      for (int i = 0; i < len; i += 1)
      y.push_back(x[(i - n + len) % len]);
      return y;
   }
   
   class PatternHistoryTableData {
   public:
      vector<bool> pattern;
      // my addition
      uint64_t way;
   };
   
   class PatternHistoryTable : public LRUSetAssociativeCache<PatternHistoryTableData> {
      typedef LRUSetAssociativeCache<PatternHistoryTableData> Super;
   
   public:
      PatternHistoryTable(int size, int pattern_len, int min_addr_width, int max_addr_width, int pc_width, int debug_level = 0, int num_ways = 16)
      : Super(size, num_ways, debug_level), pattern_len(pattern_len), min_addr_width(min_addr_width), max_addr_width(max_addr_width), pc_width(pc_width) {
        ip_0 = 0;
        ip_1 = 0;
        ip_2 = 0;
        ip_3 = 0;
         // assert(this->pc_width >= 0);
         // assert(this->min_addr_width >= 0);
         // assert(this->max_addr_width >= 0);
         // assert(this->max_addr_width >= this->min_addr_width);
         // assert(this->pc_width + this->min_addr_width > 0);
         // assert(__builtin_popcount(pattern_len) == 1);
         if (this->debug_level >= 1)
         cerr << "PatternHistoryTable::PatternHistoryTable(size=" << size << ", pattern_len=" << pattern_len
         << ", min_addr_width=" << min_addr_width << ", max_addr_width=" << max_addr_width
         << ", pc_width=" << pc_width << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")"
         << dec << endl;
               }
   
      /* NOTE: In BINGO, address is actually block number. */
      void insert(uint64_t pc, uint64_t address, vector<bool> pattern) {
         if (this->debug_level >= 2)
         cerr << "PatternHistoryTable::insert(pc=0x" << hex << pc << ", address=0x" << address
         << ", pattern=" << pattern_to_string(pattern) << ")" << dec << endl;
         // assert((int)pattern.size() == this->pattern_len);
         int offset = address % this->pattern_len;
         pattern = my_rotate(pattern, -offset);
         uint64_t key = this->build_key(pc, address);
         Super::insert(key, {pattern});
         Super::set_mru(key);
      }
   
      /**
      * First searches for a PC+Address match. If no match is found, returns all PC+Offset matches.
      * @return All un-rotated patterns if matches were found, returns an empty vector otherwise
      */
      vector<vector<bool>> find(uint64_t pc, uint64_t address) {
         if (this->debug_level >= 2)
         cerr << "PatternHistoryTable::find(pc=0x" << hex << pc << ", address=0x" << address << ")" << dec << endl;
         uint64_t key = this->build_key(pc, address);
         uint64_t index = key % this->num_sets;
         uint64_t tag = key / this->num_sets;
         auto &set = this->entries[index];
         uint64_t min_tag_mask = (1 << (this->pc_width + this->min_addr_width - this->index_len)) - 1;
         uint64_t max_tag_mask = (1 << (this->pc_width + this->max_addr_width - this->index_len)) - 1;
         vector<vector<bool>> matches;
         //FIXME: added way index vector
         way_matches.clear();

         this->last_event = MISS;
         for (int i = 0; i < this->num_ways; i += 1) {
            if (!set[i].valid)
            continue;
            bool min_match = ((set[i].tag & min_tag_mask) == (tag & min_tag_mask));
            bool max_match = ((set[i].tag & max_tag_mask) == (tag & max_tag_mask));
            vector<bool> &cur_pattern = set[i].data.pattern;
            if (max_match) {
               this->last_event = PC_ADDRESS;
               Super::set_mru(set[i].key);
               
               matches.clear();
               way_matches.clear();

               matches.push_back(cur_pattern);
               way_matches.push_back(i);
               break;
            }
            if (min_match) {
               this->last_event = PC_OFFSET;
               matches.push_back(cur_pattern);
               way_matches.push_back(i);
               
            }
         }
         int offset = address % this->pattern_len;
         for (int i = 0; i < (int)matches.size(); i += 1)
         matches[i] = my_rotate(matches[i], +offset);
         return matches;
      }
   
      Event get_last_event() { return this->last_event; }
   
      string log() {
         vector<string> headers({"PC", "Offset", "Address", "Pattern"});
         return Super::log(headers);
      }

      vector<size_t> LRU_argsort(int set_idx) {
         
         vector<uint64_t> &set = Super::lru[set_idx];
         vector<size_t> idx(set.size());
         iota(idx.begin(), idx.end(), 0);
     
         auto by_value = [&set](size_t a, size_t b)
                         { return set[a] < set[b]; };
     
         sort(idx.begin(), idx.end(), by_value);
     
         return idx;
      }

      uint64_t get_key(uint64_t pc, uint64_t address) {return this->build_key(pc, address); }
   
   private:
      /* @override */
      void write_data(Entry &entry, Table &table, int row) {
         uint64_t base_key = entry.key >> (this->pc_width + this->min_addr_width);
         uint64_t index_key = entry.key & ((1 << (this->pc_width + this->min_addr_width)) - 1);
         index_key = hash_index(index_key, this->index_len); /* unhash */
         uint64_t key = (base_key << (this->pc_width + this->min_addr_width)) | index_key;
   
         /* extract PC, offset, and address */
         uint64_t offset = key & ((1 << this->min_addr_width) - 1);
         key >>= this->min_addr_width;
         uint64_t pc = key & ((1 << this->pc_width) - 1);
         key >>= this->pc_width;
         uint64_t address = (key << this->min_addr_width) + offset;
   
         table.set_cell(row, 0, pc);
         table.set_cell(row, 1, offset);
         table.set_cell(row, 2, address);
         table.set_cell(row, 3, pattern_to_string(entry.data.pattern));
      }
   
      uint64_t build_key(uint64_t pc, uint64_t address) {
         pc &= (1 << this->pc_width) - 1;            /* use `pc_width` bits from pc */
         address &= (1 << this->max_addr_width) - 1; /* use `addr_width` bits from address */
         uint64_t offset = address & ((1 << this->min_addr_width) - 1);
         uint64_t base = (address >> this->min_addr_width);
         /* key = base + hash_index( pc + offset )
         * The index must be computed from only PC+Offset to ensure that all entries with the same
         * PC+Offset end up in the same set */
         uint64_t index_key = hash_index((pc << this->min_addr_width) | offset, this->index_len);
         uint64_t key = (base << (this->pc_width + this->min_addr_width)) | index_key;
         return key;
      }
   
      int pattern_len;
      int min_addr_width, max_addr_width, pc_width;
      Event last_event;

   public:
      vector<uint64_t> way_matches;
      uint64_t ip_0,
      ip_1,
      ip_2,
      ip_3, 
      pf_useful;



      /*======================================================*/
      /* Entry   = [tag, map, valid, LRU]                     */
      /* Storage = size * (32 - lg(sets) + 32 + 1 + lg(ways)) */
      /* 8K * (32 - lg(512) + 32 + 1 + lg(16)) = 60K Bytes    */
      /*======================================================*/
   };
   
   class PrefetchStreamerData {
   public:
      /* contains the prefetch fill level for each block of spatial region */
      vector<int> pattern;
      // FIXME: added info for filter check
      vector<int> recencies;
      vector<int> votes;
      vector<int> p_sums;
   };
   
   class PrefetchStreamer : public LRUSetAssociativeCache<PrefetchStreamerData> {
      typedef LRUSetAssociativeCache<PrefetchStreamerData> Super;
   
   public:
      //FIXME: cross pointer for pf filter
      PREFETCH_FILTER *pf_filter;

      PrefetchStreamer(int size, int pattern_len, int debug_level = 0, int num_ways = 16)
      : Super(size, num_ways, debug_level), pattern_len(pattern_len) {
         if (this->debug_level >= 1)
         cerr << "PrefetchStreamer::PrefetchStreamer(size=" << size << ", pattern_len=" << pattern_len
         << ", debug_level=" << debug_level << ", num_ways=" << num_ways << ")" << dec << endl;
      }
   
      void insert(uint64_t region_number, vector<int> pattern, vector<int> recencies, vector<int> votes, vector<int> p_sums) {
         if (this->debug_level >= 2)
         cerr << "PrefetchStreamer::insert(region_number=0x" << hex << region_number
         << ", pattern=" << pattern_to_string(pattern) << ")" << dec << endl;
         uint64_t key = this->build_key(region_number);
         Super::insert(key, {pattern, recencies, votes, p_sums});
         Super::set_mru(key);
      }
      //FIXME: added pc 
      int prefetch(CACHE *cache, uint64_t block_address, uint64_t pc) {
         if (this->debug_level >= 2) {
            cerr << "PrefetchStreamer::prefetch(cache=" << cache->NAME << ", block_address=0x" << hex << block_address
            << ")" << dec << endl;
            cerr << "[PrefetchStreamer::prefetch] " << cache->PQ.occupancy << "/" << cache->PQ.SIZE
            << " PQ entries occupied." << dec << endl;
            cerr << "[PrefetchStreamer::prefetch] " << cache->MSHR.occupancy << "/" << cache->MSHR.SIZE
            << " MSHR entries occupied." << dec << endl;
         }
         uint64_t base_addr = block_address << LOG2_BLOCK_SIZE;
         int region_offset = block_address % this->pattern_len;
         uint64_t region_number = block_address / this->pattern_len;
         uint64_t key = this->build_key(region_number);
         Entry *entry = Super::find(key);
         if (!entry) {
            if (this->debug_level >= 2)
            cerr << "[PrefetchStreamer::prefetch] No entry found." << dec << endl;
            return 0;
         }
         Super::set_mru(key);
         int pf_issued = 0;
         vector<int> &pattern = entry->data.pattern;
         // FIXME: more stuff from entry
         vector<int> &recencies = entry->data.recencies;
         vector<int> &vote_counts = entry->data.votes;
         vector<int> &p_sums = entry->data.p_sums;

         pattern[region_offset] = 0; /* accessed block will be automatically fetched if necessary (miss) */
         int pf_offset;
         /* prefetch blocks that are close to the recent access first (locality!) */
         for (int d = 1; d < this->pattern_len; d += 1) {
            /* prefer positive strides */
            for (int sgn = +1; sgn >= -1; sgn -= 2) {
               pf_offset = region_offset + sgn * d;
               if (0 <= pf_offset && pf_offset < this->pattern_len && pattern[pf_offset] > 0) {
                  uint64_t pf_address = (region_number * this->pattern_len + pf_offset) << LOG2_BLOCK_SIZE;
                  if (cache->PQ.occupancy + cache->MSHR.occupancy < cache->MSHR.SIZE - 1 && cache->PQ.occupancy < cache->PQ.SIZE) {
                     
                     // FIXME: filter check
                     FILTER_REQUEST bingo_fill = pattern[pf_offset] == FILL_L2 ? BINGO_L2C_PREFETCH : BINGO_LLC_PREFETCH;
                     if (pf_filter->check(pf_address, base_addr, pc, bingo_fill, recencies[pf_offset], vote_counts[pf_offset], p_sums[pf_offset])) {
                        cache->prefetch_line(0, base_addr, pf_address, pattern[pf_offset], 0);
                        pf_issued += 1;
                        pattern[pf_offset] = 0;   
                     }
                  } else {
                     /* prefetching limit is reached */
                     return pf_issued;
                  }
               }
            }
         }
         /* all prefetches done for this spatial region */
         Super::erase(key);
         return pf_issued;
      }
   
      string log() {
         vector<string> headers({"Region", "Pattern"});
         return Super::log(headers);
      }


   
   private:
      /* @override */
      void write_data(Entry &entry, Table &table, int row) {
         uint64_t key = hash_index(entry.key, this->index_len);
         table.set_cell(row, 0, key);
         table.set_cell(row, 1, pattern_to_string(entry.data.pattern));
      }
   
      uint64_t build_key(uint64_t region_number) { return hash_index(region_number, this->index_len); }
   
      int pattern_len;
   
      /*======================================================*/
      /* Entry   = [tag, map, valid, LRU]                     */
      /* Storage = size * (53 - lg(sets) + 64 + 1 + lg(ways)) */
      /* 128 * (53 - lg(8) + 64 + 1 + lg(16)) = 1904 Bytes    */
      /*======================================================*/
   };
   
   class Bingo_PPF : public Prefetcher {
   public:


   Bingo_PPF(string type, CACHE *cache);
      ~Bingo_PPF();
      void invoke_prefetcher(uint64_t pc, uint64_t address, uint8_t cache_hit, uint8_t type, std::vector<uint64_t> &pref_addr);
      void register_fill(uint64_t addr, uint32_t set, uint32_t way, uint8_t prefetch, uint64_t evicted_addr);
      void dump_stats();
      void print_config();
   
      /**
      * Updates BINGO's state based on the most recent LOAD access.
      * @param block_number The block address of the most recent LOAD access
      * @param pc           The PC of the most recent LOAD access
      */
      void access(uint64_t block_number, uint64_t pc);
      void eviction(uint64_t block_number);
      int prefetch(uint64_t block_number, uint64_t pc);
      void set_debug_level(int debug_level);
      void log();
   
      /*========== stats ==========*/
      /* NOTE: the BINGO code submitted for DPC3 (this code) does not call any of these methods. */
      Event get_event(uint64_t block_number);
      void add_prefetch(uint64_t block_number);
      void add_useful(uint64_t block_number, Event ev);
      void add_useless(uint64_t block_number, Event ev);
      void reset_stats();
      void print_stats();
   
   
   private:
      /**
      * Performs a PHT lookup and computes a prefetching pattern from the result.
      * @return The appropriate prefetch level for all blocks based on PHT output or an empty vector
      *         if no blocks should be prefetched
      */
      vector<vector<int>> find_in_pht(uint64_t pc, uint64_t address);
   
      void insert_in_pht(const AccumulationTable::Entry &entry);
   
      /**
      * Uses a voting mechanism to produce a prefetching pattern from a set of footprints.
      * @param x The patterns obtained from all PC+Offset matches
      * @return  The appropriate prefetch level for all blocks based on BINGO's voting thresholds or
      *          an empty vector if no blocks should be prefetched
      */
      vector<int> vote(const vector<vector<bool>> &x);
      vector<vector<int>> Bingo_PPF::count_votes(const vector<vector<bool>> &x, uint64_t index);

      void init_knobs();
      void init_stats();
   
      /*======================*/
      CACHE *parent = NULL;
      int pattern_len;
      FilterTable filter_table;
      AccumulationTable accumulation_table;
      PatternHistoryTable pht;
      PrefetchStreamer pf_streamer;
      int debug_level = 0;
      uint32_t pc_address_fill_level;
      // FIXME: PERCEPTRON initialization
      bingo_helper::PERCEPTRON PERC;
      bingo_helper::PREFETCH_FILTER pf_filter;
      

      /* stats */
      unordered_map<uint64_t, Event> pht_events;
   
      uint64_t pht_access_cnt = 0;
      uint64_t pht_pc_address_cnt = 0;
      uint64_t pht_pc_offset_cnt = 0;
      uint64_t pht_miss_cnt = 0;
   
      uint64_t prefetch_cnt[2] = {0};
      uint64_t useful_cnt[2] = {0};
      uint64_t useless_cnt[2] = {0};
   
      unordered_map<int, uint64_t> pref_level_cnt;
      uint64_t region_pref_cnt = 0;
   
      uint64_t vote_cnt = 0;
      uint64_t voter_sum = 0;
      uint64_t voter_sqr_sum = 0;
   };
   
namespace bingo_helper {

  // FIXME: PERCEPTRON CLASS
class PERCEPTRON
{
public:
    // Perc Weights
    int32_t perc_weights[PERC_ENTRIES][PERC_FEATURES];
   

    // CONST depths for different features
    int32_t PERC_DEPTH[PERC_FEATURES];

    int min_addr_width, max_addr_width, pc_width, pht_size, pht_ways, index_len, pattern_len;

    PERCEPTRON(int min_addr_width, int max_addr_width, int pc_width, int pht_size, int pht_ways, int index_len, int pattern_len) 
    : min_addr_width(min_addr_width), max_addr_width(max_addr_width), pc_width(pc_width), pht_size(pht_size), pht_ways(pht_ways), index_len(index_len), pattern_len(pattern_len)
    {

        cout << "\nInitialize PERCEPTRON" << endl;
        cout << "PERC_ENTRIES: " << PERC_ENTRIES << endl;
        cout << "PERC_FEATURES: " << PERC_FEATURES << endl;

        int pc_address_size = pow(2, pc_width + max_addr_width - index_len) - 1;
        pc_address_size = min((pc_address_size), PERC_ENTRIES);

        // "lower bits of the physical address of the demand access that triggers the prefetch"
        PERC_DEPTH[0] = 2048; //base_addr; Physical Address
        PERC_DEPTH[1] = pht_ways; // Vote Count | address is Cache Line for now FIXME:
        PERC_DEPTH[2] = 4096; //page_addr; Page Address
        // FIXME: new:
        PERC_DEPTH[3] = 4096; // "PC+Address" 
        PERC_DEPTH[4] = 4096; // "PC+Offset", 
        PERC_DEPTH[5] = 4096; //ip_1 ^ ip_2 ^ ip_3; PC1 XOR PC2»1 XOR PC3»2
        // FIXME: new:
        PERC_DEPTH[6] = pht_ways; // Average Recency;
      //   PERC_DEPTH[7] = pht_ways; // Vote Count;

        for (int i = 0; i < PERC_ENTRIES; i++)
        {
            for (int j = 0; j < PERC_FEATURES; j++)
            {
                perc_weights[i][j] = 0;
            }
        }
    }

    void perc_update(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count, bool direction, int32_t perc_sum);
    int32_t perc_predict(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count);
    void get_perc_index(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, uint64_t avg_recency, uint64_t vote_count, uint64_t perc_set[PERC_FEATURES]);
   //  uint64_t build_key(uint64_t pc, uint64_t address);
  };

class PREFETCH_FILTER
{
public:
    /* cross-reference pointers */
    // GLOBAL_REGISTER *ghr; // one of these went in the signature table, no longer passed in read_and_update_sig()
    PatternHistoryTable *hist;
    PERCEPTRON *perc;

    uint64_t remainder_tag[FILTER_SET],
        pc[FILTER_SET],
        pc_1[FILTER_SET],
        pc_2[FILTER_SET],
        pc_3[FILTER_SET],
        address[FILTER_SET],
        // FIXME: added features
        avg_recency[FILTER_SET],
        vote_count[FILTER_SET];
    bool valid[FILTER_SET], // Consider this as "prefetched"
        useful[FILTER_SET]; // Consider this as "used"
    int32_t perc_sum[FILTER_SET]; //delta[FILTER_SET],
        
    // uint32_t last_signature[FILTER_SET],
    //     confidence[FILTER_SET],
    //     cur_signature[FILTER_SET],
    //     la_depth[FILTER_SET];

    uint64_t remainder_tag_reject[FILTER_SET_REJ],
        pc_reject[FILTER_SET_REJ],
        pc_1_reject[FILTER_SET_REJ],
        pc_2_reject[FILTER_SET_REJ],
        pc_3_reject[FILTER_SET_REJ],
        address_reject[FILTER_SET_REJ],
        // FIXME: added features
        avg_recency_reject[FILTER_SET],
        vote_count_reject[FILTER_SET];
    bool valid_reject[FILTER_SET_REJ]; // Entries which the perceptron rejected
    int32_t //delta_reject[FILTER_SET_REJ],
        perc_sum_reject[FILTER_SET_REJ];
    // uint32_t last_signature_reject[FILTER_SET_REJ],
    //     confidence_reject[FILTER_SET_REJ],
    //     cur_signature_reject[FILTER_SET_REJ],
    //     la_depth_reject[FILTER_SET_REJ];

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

    bool check(uint64_t check_addr, uint64_t base_addr, uint64_t ip, FILTER_REQUEST filter_request, uint64_t recency, uint64_t votess, int32_t p_sum);


private:
uint64_t get_hash(uint64_t key)
{
// TODO: Find a good 64-bit hash function FIXME: this is from the OG code
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


};
}

// }

/////////////////////////////////////////////// PPF MODS START ////////////////////////////////////////////////// 


// namespace bingo_ppf {

//#define SPP_PERC_WGHT
// #ifdef BINGO_PERC_WGHT
// #define BINGO_PW(x) x
// #else 
// #define BINGO_PW(x)
// #endif



// #define PAGES_TRACKED 6



// uint64_t page_tracker[PAGES_TRACKED];
/////////////////////////////////////////////////


/* In pattern table:
    /* cross-reference pointers [*]/
    GLOBAL_REGISTER *ghr;
    PERCEPTRON *perc;
    PREFETCH_FILTER *filter;
    
    
    additions to read_pattern() args:
    int32_t *perc_sum_q, uint64_t addr, uint64_t base_addr, uint64_t train_addr, uint64_t curr_ip, int32_t train_delta, uint32_t last_sig, uint32_t pq_occupancy, uint32_t pq_SIZE, uint32_t mshr_occupancy, uint32_t mshr_SIZE
*/

/////////////////////////////////////////////// ^^ PPF MODS END ^^  //////////////////////////////////////////////////


#endif /* BINGO_PPF_H */
