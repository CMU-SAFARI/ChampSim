//=======================================================================================//
// File             : sms/sms.cc
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 29/SEP/2025
// Description      : Implements IPCP, ISCA'20
//=======================================================================================//

#include "ipcp.h"

#include <chrono>
#include <iostream>

#include "cache.h"

void ipcp::prefetcher_initialize()
{
  std::cout << "IPCP_AT_L1_CONFIG" << std::endl
            << "NUM_IP_TABLE_L1_ENTRIES " << NUM_IP_TABLE_L1_ENTRIES << std::endl
            << "NUM_GHB_ENTRIES " << NUM_GHB_ENTRIES << std::endl
            << "NUM_IP_INDEX_BITS " << NUM_IP_INDEX_BITS << std::endl
            << "NUM_IP_TAG_BITS " << NUM_IP_TAG_BITS << std::endl
            << "S_TYPE " << S_TYPE << std::endl
            << "CS_TYPE " << CS_TYPE << std::endl
            << "CPLX_TYPE " << CPLX_TYPE << std::endl
            << "NL_TYPE " << NL_TYPE << std::endl
            << std::endl;
}

uint32_t ipcp::prefetcher_cache_operate(champsim::address address, champsim::address ip_addr, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                        bool is_instr, uint32_t metadata_in)
{
  uint64_t addr = address.to<uint64_t>();
  uint64_t ip = ip_addr.to<uint64_t>();
  uint64_t curr_page = addr >> LOG2_PAGE_SIZE;
  uint64_t cl_addr = addr >> LOG2_BLOCK_SIZE;
  uint64_t cl_offset = (addr >> LOG2_BLOCK_SIZE) & 0x3F;
  uint16_t signature = 0, last_signature = 0;
  int prefetch_degree = 0;
  int spec_nl_threshold = 0;
  int num_prefs = 0;
  uint32_t metadata = 0;
  uint16_t ip_tag = (ip >> NUM_IP_INDEX_BITS) & ((1 << NUM_IP_TAG_BITS) - 1);

  prefetch_degree = 3;
  spec_nl_threshold = 15;

  // update miss counter
  if (cache_hit == 0)
    num_misses += 1;

  // get current CPU cycle
  auto ct = intern_->current_time.time_since_epoch() / intern_->clock_period;

  // update spec nl bit when num misses crosses certain threshold
  if (num_misses == 256) {
    mpkc = ((float)num_misses / (float)(ct - prev_cpu_cycle)) * 1000;
    prev_cpu_cycle = ct;
    if (mpkc > (float)spec_nl_threshold)
      spec_nl = 0;
    else
      spec_nl = 1;
    num_misses = 0;
  }

  // calculate the index bit
  int index = ip & ((1 << NUM_IP_INDEX_BITS) - 1);
  if (trackers_l1[index].ip_tag != ip_tag) { // new/conflict IP
    if (trackers_l1[index].ip_valid == 0) {  // if valid bit is zero, update with latest IP info
      trackers_l1[index].ip_tag = ip_tag;
      trackers_l1[index].last_page = curr_page;
      trackers_l1[index].last_cl_offset = cl_offset;
      trackers_l1[index].last_stride = 0;
      trackers_l1[index].signature = 0;
      trackers_l1[index].conf = 0;
      trackers_l1[index].str_valid = 0;
      trackers_l1[index].str_strength = 0;
      trackers_l1[index].str_dir = 0;
      trackers_l1[index].ip_valid = 1;
    } else { // otherwise, reset valid bit and leave the previous IP as it is
      trackers_l1[index].ip_valid = 0;
    }

    // issue a next line prefetch upon encountering new IP
    uint64_t pf_address = ((addr >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE; // BASE NL=1, changing it to 3
    metadata = encode_metadata(1, NL_TYPE, spec_nl);
    intern_->prefetch_line(champsim::address{pf_address}, true, metadata);
    return 0;
  } else { // if same IP encountered, set valid bit
    trackers_l1[index].ip_valid = 1;
  }

  // calculate the stride between the current address and the last address
  int64_t stride = 0;
  if (cl_offset > trackers_l1[index].last_cl_offset)
    stride = cl_offset - trackers_l1[index].last_cl_offset;
  else {
    stride = trackers_l1[index].last_cl_offset - cl_offset;
    stride *= -1;
  }

  // don't do anything if same address is seen twice in a row
  if (stride == 0)
    return 0;

  // page boundary learning
  if (curr_page != trackers_l1[index].last_page) {
    if (stride < 0)
      stride += 64;
    else
      stride -= 64;
  }

  // update constant stride(CS) confidence
  trackers_l1[index].conf = update_conf((int)stride, (int)trackers_l1[index].last_stride, trackers_l1[index].conf);

  // update CS only if confidence is zero
  if (trackers_l1[index].conf == 0)
    trackers_l1[index].last_stride = stride;

  last_signature = trackers_l1[index].signature;
  // update complex stride(CPLX) confidence
  DPT_l1[last_signature].conf = update_conf((int)stride, DPT_l1[last_signature].delta, DPT_l1[last_signature].conf);

  // update CPLX only if confidence is zero
  if (DPT_l1[last_signature].conf == 0)
    DPT_l1[last_signature].delta = (int)stride;

  // calculate and update new signature in IP table
  signature = update_sig_l1(last_signature, (int)stride);
  trackers_l1[index].signature = signature;

  // check GHB for stream IP
  check_for_stream_l1(index, cl_addr);

  SIG_DP(cout << ip << ", " << cache_hit << ", " << cl_addr << ", " << addr << ", " << stride << "; ";
         cout << last_signature << ", " << DPT_l1[last_signature].delta << ", " << DPT_l1[last_signature].conf << "; ";
         cout << trackers_l1[index].last_stride << ", " << stride << ", " << trackers_l1[index].conf << ", " << "; ";);

  if (trackers_l1[index].str_valid == 1) { // stream IP
                                           // for stream, prefetch with twice the usual degree
    prefetch_degree = prefetch_degree * 2;
    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = 0;

      if (trackers_l1[index].str_dir == 1) { // +ve stream
        pf_address = (cl_addr + i + 1) << LOG2_BLOCK_SIZE;
        metadata = encode_metadata(1, S_TYPE, spec_nl); // stride is 1
      } else {                                          // -ve stream
        pf_address = (cl_addr - i - 1) << LOG2_BLOCK_SIZE;
        metadata = encode_metadata(-1, S_TYPE, spec_nl); // stride is -1
      }

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr >> LOG2_PAGE_SIZE)) {
        break;
      }

      intern_->prefetch_line(champsim::address{pf_address}, true, metadata);
      num_prefs++;
      SIG_DP(cout << "1, ");
    }

  } else if (trackers_l1[index].conf > 1 && trackers_l1[index].last_stride != 0) { // CS IP
    for (int i = 0; i < prefetch_degree; i++) {
      uint64_t pf_address = (cl_addr + (trackers_l1[index].last_stride * (i + 1))) << LOG2_BLOCK_SIZE;

      // Check if prefetch address is in same 4 KB page
      if ((pf_address >> LOG2_PAGE_SIZE) != (addr >> LOG2_PAGE_SIZE)) {
        break;
      }

      metadata = encode_metadata((int)trackers_l1[index].last_stride, CS_TYPE, spec_nl);
      intern_->prefetch_line(champsim::address{pf_address}, true, metadata);
      num_prefs++;
      SIG_DP(cout << trackers_l1[index].last_stride << ", ");
    }
  } else if (DPT_l1[signature].conf >= 0 && DPT_l1[signature].delta != 0) { // if conf>=0, continue looking for delta
    int pref_offset = 0, i = 0;                                             // CPLX IP
    for (i = 0; i < prefetch_degree; i++) {
      pref_offset += DPT_l1[signature].delta;
      uint64_t pf_address = ((cl_addr + pref_offset) << LOG2_BLOCK_SIZE);

      // Check if prefetch address is in same 4 KB page
      if (((pf_address >> LOG2_PAGE_SIZE) != (addr >> LOG2_PAGE_SIZE)) || (DPT_l1[signature].conf == -1) || (DPT_l1[signature].delta == 0)) {
        // if new entry in DPT or delta is zero, break
        break;
      }

      // we are not prefetching at L2 for CPLX type, so encode delta as 0
      metadata = encode_metadata(0, CPLX_TYPE, spec_nl);
      if (DPT_l1[signature].conf > 0) { // prefetch only when conf>0 for CPLX
        intern_->prefetch_line(champsim::address{pf_address}, true, metadata);
        num_prefs++;
        SIG_DP(cout << pref_offset << ", ");
      }
      signature = update_sig_l1(signature, DPT_l1[signature].delta);
    }
  }

  // if no prefetches are issued till now, speculatively issue a next_line prefetch
  if (num_prefs == 0 && spec_nl == 1) { // NL IP
    uint64_t pf_address = ((addr >> LOG2_BLOCK_SIZE) + 1) << LOG2_BLOCK_SIZE;
    metadata = encode_metadata(1, NL_TYPE, spec_nl);
    intern_->prefetch_line(champsim::address{pf_address}, true, metadata);
    SIG_DP(cout << "1, ");
  }

  SIG_DP(cout << std::endl);

  // update the IP table entries
  trackers_l1[index].last_cl_offset = cl_offset;
  trackers_l1[index].last_page = curr_page;

  // update GHB
  // search for matching cl addr
  int ghb_index = 0;
  for (ghb_index = 0; ghb_index < NUM_GHB_ENTRIES; ghb_index++)
    if (cl_addr == ghb_l1[ghb_index])
      break;
  // only update the GHB upon finding a new cl address
  if (ghb_index == NUM_GHB_ENTRIES) {
    for (ghb_index = NUM_GHB_ENTRIES - 1; ghb_index > 0; ghb_index--)
      ghb_l1[ghb_index] = ghb_l1[ghb_index - 1];
    ghb_l1[0] = cl_addr;
  }

  return 0;
}

uint32_t ipcp::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, bool is_instr, champsim::address evicted_addr,
                                     uint32_t metadata_in)
{
  return 0;
}
void ipcp::prefetcher_cycle_operate() {}

/***************Updating the signature*************************************/
uint16_t ipcp::update_sig_l1(uint16_t old_sig, int delta)
{
  uint16_t new_sig = 0;
  int sig_delta = 0;

  // 7-bit sign magnitude form, since we need to track deltas from +63 to -63
  sig_delta = (delta < 0) ? (((-1) * delta) + (1 << 6)) : delta;
  new_sig = ((old_sig << 1) ^ sig_delta) & 0xFFF; // 12-bit signature

  return new_sig;
}

/****************Encoding the metadata***********************************/
uint32_t ipcp::encode_metadata(int stride, uint16_t type, int _spec_nl)
{
  uint32_t metadata = 0;

  // first encode stride in the last 8 bits of the metadata
  if (stride > 0)
    metadata = stride;
  else
    metadata = ((-1 * stride) | 0b1000000);

  // encode the type of IP in the next 4 bits
  metadata = metadata | (type << 8);

  // encode the speculative NL bit in the next 1 bit
  metadata = metadata | (_spec_nl << 12);

  return metadata;
}

/*********************Checking for a global stream (GS class)***************/

void ipcp::check_for_stream_l1(int index, uint64_t cl_addr)
{
  int pos_count = 0, neg_count = 0, count = 0;
  uint64_t check_addr = cl_addr;

  // check for +ve stream
  for (int i = 0; i < NUM_GHB_ENTRIES; i++) {
    check_addr--;
    for (int j = 0; j < NUM_GHB_ENTRIES; j++)
      if (check_addr == ghb_l1[j]) {
        pos_count++;
        break;
      }
  }

  check_addr = cl_addr;
  // check for -ve stream
  for (int i = 0; i < NUM_GHB_ENTRIES; i++) {
    check_addr++;
    for (int j = 0; j < NUM_GHB_ENTRIES; j++)
      if (check_addr == ghb_l1[j]) {
        neg_count++;
        break;
      }
  }

  if (pos_count > neg_count) { // stream direction is +ve
    trackers_l1[index].str_dir = 1;
    count = pos_count;
  } else { // stream direction is -ve
    trackers_l1[index].str_dir = 0;
    count = neg_count;
  }

  if (count > NUM_GHB_ENTRIES / 2) { // stream is detected
    trackers_l1[index].str_valid = 1;
    if (count >= (NUM_GHB_ENTRIES * 3) / 4) // stream is classified as strong if more than 3/4th entries belong to stream
      trackers_l1[index].str_strength = 1;
  } else {
    if (trackers_l1[index].str_strength == 0) // if identified as weak stream, we need to reset
      trackers_l1[index].str_valid = 0;
  }
}

/**************************Updating confidence for the CS class****************/
int ipcp::update_conf(int stride, int pred_stride, int conf)
{
  if (stride == pred_stride) { // use 2-bit saturating counter for confidence
    conf++;
    if (conf > 3)
      conf = 3;
  } else {
    conf--;
    if (conf < 0)
      conf = 0;
  }

  return conf;
}
