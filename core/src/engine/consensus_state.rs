/*
 * Copyright 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

use engine::consensus_state_store::ConsensusStateStore;
use engine::wait_time_cache::WaitTimeCache;
use poet2_util;
use sawtooth_sdk::consensus::engine::*;
use service::Poet2Service;
use std::collections::HashMap;
use std::collections::VecDeque;
use protos::validator_registry::{
    ValidatorInfo,
};
use validator_registry_view;

/*
*  The validator state represents the state for a single
*  validator at a point in time.  A validator state object contains:
*  key_block_claim_count (int): The number of blocks that the validator has
*  claimed using the current PoET public key
*  poet_public_key (str): The current PoET public key for the validator
*  total_block_claim_count (int): The total number of the blocks that the
*      validator has claimed
*
*/
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ValidatorState {
    pub key_block_claim_count: u64,
    pub poet_public_key: String,
    pub total_block_claim_count: u64,
}

/*
* The population sample represents the information
* we need to create the population estimate, which in turn is used to compute
* the local mean.  A population sample object contains:
* wait_time (float): The duration from a wait certificate/timer
* local_mean (float): The local mean from a wait certificate/timer
*/

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PopulationSample {
    wait_time: u64,
    local_mean: f64,
}

/*
*
* The population estimate represents what we need
* to help in computing zTest results.  A population estimate object contains:
*
* population_estimate (float): The population estimate for the corresponding
*     block
* previous_block_id (str): The ID of the block previous to the one that this
*     population estimate corresponds to
* validator_id (str): The ID of the validator that won the corresponding
*     block
*
*/
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct EstimateInfo {
    pub population_estimate: f64,
    // Needs to be of type BlockId but encapsulating structure is required to
    // to be serializeable & BlockId is not at the sdk
    pub previous_block_id: String,
    pub validator_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ConsensusState {
    pub population_sample: PopulationSample,
    pub estimate_info: EstimateInfo,
    pub population_estimate_cache: HashMap<String, EstimateInfo>,
    pub total_block_claim_count: u64,
    pub validators: HashMap<String, ValidatorState>,
    pub aggregate_chain_clock: u64,
    pub aggregate_local_mean: f64,
    pub population_samples: VecDeque<PopulationSample>,
}

#[derive(Clone, Debug, Default)]
struct BlockInfo {
    wait_certificate: Option<String>,
    validator_info: Option<ValidatorInfo>,
}

#[derive(Clone, Default, Debug)]
struct Entry {
    key: BlockId,
    value: BlockInfo,
}

impl ConsensusState {
    pub fn consensus_state_for_block(
        for_block: &Block,
        poet2_service: &mut Poet2Service,
        consensus_state_store: &mut ConsensusStateStore,
        wait_time_cache: &mut WaitTimeCache,
    ) -> Option<ConsensusState> {
        let mut blocks: Vec<Entry> = Vec::new();
        let mut cur_block: Block = for_block.clone();
        let mut cur_block_id = cur_block.block_id.clone();
        let mut prev_wait_cert: Option<String> = None;
        let mut consensus_state: Option<ConsensusState>;
        let mut consensus_state_raw: ConsensusState;

        loop {
            // Get the consensus state from consensus state store
            consensus_state = match consensus_state_store.get(&cur_block_id) {
                Ok(result) => Some(*result),
                Err(_) => {
                    debug!("Failed to retrieve state from state store. Creating a new one for block_id: {}",
                        poet2_util::to_hex_string(&cur_block_id));
                    None
                }
            };

            if consensus_state.is_some() {
                debug!(
                    "Found a consensus state entry for block_id: {}. Stopping and returning.",
                    poet2_util::to_hex_string(&cur_block_id)
                );
                break;
            }

            let (cur_wait_cert, _cur_wait_cert_sign) = if cur_block.block_num == 0 {
                (String::new(), String::new())
            } else {
                poet2_util::get_cert_and_sig_from(&cur_block)
            };

            if cur_wait_cert.is_empty() {
                warn!("Wait certificate is empty"); // non-poet block
                if blocks.is_empty() || prev_wait_cert.is_some() {
                    blocks.push(Entry {
                        key: cur_block_id.clone(),
                        value: BlockInfo {
                            wait_certificate: None,
                            validator_info: None,
                        },
                    });
                }
            } else {
                let cur_block_validator_id = poet2_util::to_hex_string(&cur_block.signer_id);
                // Get validator info for validator_id at current block_id
                let cur_validator_info =
                    validator_registry_view::get_validator_info_for_validator_id(
                        cur_block_validator_id.as_str(),
                        &cur_block_id.to_owned(),
                        poet2_service,
                    );
                if cur_validator_info.is_err() {
                    debug!(
                        "Cannot find registry entry for block_id: {}",
                        poet2_util::to_hex_string(&cur_block_id)
                    );
                }
                debug!(
                    "Building consensus state for block_id: {}",
                    poet2_util::to_hex_string(&cur_block_id)
                );

                blocks.push(Entry {
                    key: cur_block_id.clone(),
                    value: BlockInfo {
                        wait_certificate: Some(cur_wait_cert.clone()),
                        validator_info: Some(cur_validator_info.unwrap().clone()),
                    },
                });
            }

            if cur_block.block_num == 0 {
                debug!("Reached genesis! Breaking out of loop...");
                break;
            }

            prev_wait_cert = Some(cur_wait_cert.clone());

            // Set cur_block id to cur_block's previous block id for next iteration
            let prev_block_id = cur_block.previous_id.clone();

            // Set cur_block
            // Find the previous block in block cache

            warn!("Finding block for current blocks previous block id");
            // find from service
            cur_block = poet2_service
                .get_block(&prev_block_id)
                .expect("Failed to get a block!");
            cur_block_id = prev_block_id.clone();
        }

        if consensus_state.is_none() {
            consensus_state = Some(ConsensusState::default());
        }

        debug!("Staring the updation of states");
        for entry in blocks.iter().rev() {
            let mut value = &entry.value;
            let mut key: BlockId = entry.key.clone();
            if value.wait_certificate.is_none() {
                consensus_state = Some(ConsensusState::default());
            } else {
                // Update aggregate_chain_clock
                // Find the correct block containing the key
                cur_block = poet2_service
                    .get_block(&key)
                    .expect("Failed to get a block!");

                let prev_block_id = cur_block.previous_id.clone();
                let prev_consensus_state: Option<ConsensusState> =
                    match consensus_state_store.get(&prev_block_id) {
                        Ok(state) => Some(*state),
                        Err(_) => {
                            // This means this is either the first block
                            // Or it was a non-poet block
                            debug!(
                                "Could not get state for block_id : {}",
                                poet2_util::to_hex_string(&key)
                            );
                            None
                        }
                    };

                let prev_aggregate_wait_time: u64 = if prev_consensus_state.is_some() {
                    prev_consensus_state
                        .clone()
                        .unwrap()
                        .aggregate_chain_clock
                        .clone()
                } else {
                    0 // reset aggregate wait time if non-poet block found in between
                };

                let cur_wait_time = wait_time_cache.get_wait_time_for(&cur_block);
                consensus_state_raw = consensus_state.unwrap();
                consensus_state_raw.aggregate_chain_clock =
                    prev_aggregate_wait_time + cur_wait_time;
                consensus_state_raw.estimate_info = EstimateInfo {
                    population_estimate: 0_f64,
                    previous_block_id: poet2_util::to_hex_string(&Vec::from(
                        cur_block.previous_id.clone(),
                    )),
                    validator_id: poet2_util::to_hex_string(&Vec::from(
                        cur_block.signer_id.clone(),
                    )),
                };

                // update k-counts
                consensus_state_raw.validator_did_claim_block(
                    &(value.clone().validator_info.unwrap()),
                    &(value.clone().wait_certificate.unwrap()),
                );
                consensus_state = Some(consensus_state_raw.clone());
                match consensus_state_store.put(&key.to_vec(), consensus_state_raw) {
                    Ok(_) => {}
                    Err(err) => {
                        panic!(
                            "Could not persist state for block_id : {}. Error : {}",
                            poet2_util::to_hex_string(&key),
                            err
                        );
                    }
                }
            }
        }

        consensus_state
    }

    pub fn validator_did_claim_block(
        &mut self,
        _validator_info: &ValidatorInfo,
        _wait_certificate: &String,
    ) -> () {
        //self.aggregate_local_mean += 5.5_f64; //wait_certificate.local_mean;
        self.total_block_claim_count += 1;
        //self.population_samples.push_back(PopulationSample {
        //    wait_time: wait_certificate.wait_time,
        //    local_mean: 5.5_f64,
        //}); //wait_certificate.local_mean});
        //while self.population_samples.len() > poet_settings_view.population_estimate_sample_size {
        //    self.population_samples.pop_front();
        // }

        // Get the current validator state
        let validator_state = self.get_validator_state(_validator_info.clone());
        let total_block_claim_count = validator_state.total_block_claim_count + 1;
        let key_block_claim_count =
            if _validator_info.get_signup_info().get_poet_public_key() == validator_state.poet_public_key {
                validator_state.key_block_claim_count + 1
            } else {
                1
            };
        let peerid_str = _validator_info.clone().id;
        self.validators.insert(
            peerid_str,
            ValidatorState {
                key_block_claim_count,
                poet_public_key: _validator_info.get_signup_info().get_poet_public_key().to_string().clone(),
                total_block_claim_count,
            },
        );
    }

    pub fn get_validator_state(
        &mut self,
        validator_info: ValidatorInfo,
    ) -> Box<ValidatorState> {
        let peerid_str = validator_info.clone().id;
        let validator_state = self.validators.get(&peerid_str);
        let val_state = ValidatorState {
            key_block_claim_count: 0,
            poet_public_key: validator_info.get_signup_info().get_poet_public_key().to_string().clone(),
            total_block_claim_count: 0,
        };
        if validator_state.is_none() {
            return Box::new(val_state);
        }
        Box::new(validator_state.unwrap().clone())
    }
}
