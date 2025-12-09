//=======================================================================================//
// File             : sms/sms.h
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 19/AUG/2025
// Description      : Implements Spatial Memory Streaming prefetcher, ISCA'06
//=======================================================================================//

#ifndef __SMS_H__
#define __SMS_H__

#include <deque>
#include <vector>

#include "champsim.h"
#include "modules.h"
#include "sms_helper.h"

struct sms : public champsim::modules::prefetcher {
private:
  // config
  constexpr static uint32_t AT_SIZE = 32;
  constexpr static uint32_t FT_SIZE = 64;
  constexpr static uint32_t PHT_SIZE = 2048;
  constexpr static uint32_t PHT_ASSOC = 16;
  constexpr static uint32_t PHT_SETS = PHT_SIZE / PHT_ASSOC;
  constexpr static uint32_t PREF_DEGREE = 4;
  constexpr static uint32_t REGION_SIZE = 2048;
  constexpr static uint32_t REGION_SIZE_LOG = 11;
  constexpr static uint32_t PREF_BUFFER_SIZE = 256;

  // internal data structures
  std::deque<FTEntry*> filter_table;
  std::deque<ATEntry*> acc_table;
  std::vector<std::deque<PHTEntry*>> pht;
  uint32_t pht_sets;
  std::deque<uint64_t> pref_buffer;

  // private functions
  std::deque<FTEntry*>::iterator search_filter_table(uint64_t page);
  std::deque<FTEntry*>::iterator search_victim_filter_table();
  void evict_filter_table(std::deque<FTEntry*>::iterator victim);
  void insert_filter_table(uint64_t pc, uint64_t page, uint32_t offset);

  std::deque<ATEntry*>::iterator search_acc_table(uint64_t page);
  std::deque<ATEntry*>::iterator search_victim_acc_table();
  void evict_acc_table(std::deque<ATEntry*>::iterator victim);
  void update_age_acc_table(std::deque<ATEntry*>::iterator current);
  void insert_acc_table(FTEntry* ftentry, uint32_t offset);

  std::deque<PHTEntry*>::iterator search_pht(uint64_t signature, uint32_t& set);
  std::deque<PHTEntry*>::iterator search_victim_pht(int32_t set);
  void evcit_pht(int32_t set, std::deque<PHTEntry*>::iterator victim);
  void update_age_pht(int32_t set, std::deque<PHTEntry*>::iterator current);
  void insert_pht_table(ATEntry* atentry);

  uint64_t create_signature(uint64_t pc, uint32_t offset);
  std::size_t generate_prefetch(uint64_t pc, uint64_t address, uint64_t page, uint32_t offset, std::vector<uint64_t>& pref_addr);
  void buffer_prefetch(std::vector<uint64_t> pref_addr);
  void issue_prefetch();

public:
  using champsim::modules::prefetcher::prefetcher;

  // champsim interface prototypes
  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type, bool is_instr,
                                    uint32_t metadata_in);
  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, bool is_instr, champsim::address evicted_addr,
                                 uint32_t metadata_in);
  void prefetcher_cycle_operate();
};

#endif /* __SMS_H__ */
