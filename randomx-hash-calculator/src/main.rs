use std::time::Instant;

use ccp_randomx::{
    bindings::{
        cache::{randomx_alloc_cache, randomx_init_cache, randomx_release_cache},
        dataset::{randomx_alloc_dataset, randomx_dataset_item_count, randomx_init_dataset},
        vm::{
            randomx_calculate_hash_first, randomx_calculate_hash_last, randomx_calculate_hash_next,
            randomx_create_vm,
        },
    },
    RandomXFlags, ResultHash,
};
use ccp_shared::types::{GlobalNonce, LocalNonce};
use ccp_shared::{types::CUID, RANDOMX_RESULT_SIZE};
use ccp_utils::hash::compute_global_nonce_cu;
use clap::Parser;

#[derive(Parser, Clone, Debug)]
struct Args {
    #[arg(long)]
    enable_msr: bool,
}

pub(crate) trait NonceIterable {
    /// Generates the next nonce.
    fn next(&mut self);

    /// Returns back to the previous nonce/
    fn prev(&mut self);
}

impl NonceIterable for LocalNonce {
    fn next(&mut self) {
        let mut nonce_as_u64: u64 = u64::from_le_bytes(
            self.as_mut()[0..std::mem::size_of::<u64>()]
                .try_into()
                .unwrap(),
        );
        nonce_as_u64 = nonce_as_u64.wrapping_add(1);
        self.as_mut()[0..std::mem::size_of::<u64>()]
            .copy_from_slice(&u64::to_le_bytes(nonce_as_u64));
    }

    fn prev(&mut self) {
        let mut nonce_as_u64: u64 = u64::from_le_bytes(
            self.as_mut()[0..std::mem::size_of::<u64>()]
                .try_into()
                .unwrap(),
        );
        nonce_as_u64 = nonce_as_u64.wrapping_sub(1);
        self.as_mut()[0..std::mem::size_of::<u64>()]
            .copy_from_slice(&u64::to_le_bytes(nonce_as_u64));
    }
}

// The current setup calculates one RandomX hash with given nonces.
fn main() {
    let Args { enable_msr } = Args::parse();
    let flags = RandomXFlags::recommended_full_mem();
    println!("{:?}", flags);

    let hex_array: [u8; 32] = [
        0x7a, 0x55, 0xef, 0x51, 0x4e, 0x78, 0x14, 0x7c, 0xed, 0x93, 0x28, 0x21, 0x0a, 0x5a, 0x83,
        0x25, 0x2c, 0xaf, 0xa8, 0x96, 0x1e, 0xa1, 0x42, 0x99, 0x4b, 0xe7, 0xbb, 0x85, 0x18, 0xf6,
        0x11, 0x32,
    ];
    let mut local_nonce = LocalNonce::new(hex_array);

    let hex_array: [u8; 32] = [
        0x06, 0x48, 0xfb, 0x77, 0x5e, 0x2c, 0x0a, 0xcd, 0xe0, 0xa6, 0x67, 0x09, 0x32, 0x89, 0x1c,
        0xc5, 0x92, 0x3a, 0x86, 0xba, 0x00, 0x66, 0x25, 0x21, 0x0b, 0x1f, 0xc7, 0xc9, 0x1a, 0x04,
        0x47, 0x4c,
    ];
    let global_nonce = GlobalNonce::new(hex_array);

    let hex_array: [u8; 32] = [
        0x50, 0x56, 0x31, 0x31, 0x3a, 0x70, 0x30, 0x3a, 0x75, 0x30, 0x3a, 0x31, 0x37, 0x31, 0x31,
        0x35, 0x33, 0x31, 0x30, 0x36, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let cu_id = CUID::new(hex_array);

    let global_nonce_cu = compute_global_nonce_cu(&global_nonce, &cu_id);

    let mut hash: [u8; RANDOMX_RESULT_SIZE] = [0; 32];

    let hashes_number = 1;
    unsafe {
        let before_init = Instant::now();

        let cache = randomx_alloc_cache(flags.bits());
        randomx_init_cache(
            cache,
            global_nonce_cu.as_ptr() as *const std::ffi::c_void,
            global_nonce_cu.len(),
        );
        let dataset = randomx_alloc_dataset(flags.bits());
        let items_count = randomx_dataset_item_count();
        randomx_init_dataset(dataset, cache, 0, items_count);
        // randomx_release_cache(cache);
        let duration = before_init.elapsed();
        println!("init: {:?}", duration);

        let vm = randomx_create_vm(flags.bits(), cache, dataset);

        let start = Instant::now();

        randomx_calculate_hash_first(
            vm,
            local_nonce.as_ref().as_ptr() as *const std::ffi::c_void,
            local_nonce.as_ref().len(),
        );

        for _ in 0..hashes_number {
            local_nonce.next();
            randomx_calculate_hash_next(
                vm,
                local_nonce.as_ref().as_ptr() as *const std::ffi::c_void,
                local_nonce.as_ref().len(),
                hash.as_mut_ptr() as *mut std::ffi::c_void,
            );
            let iter_hash = ResultHash::from_slice(hash);
            println!("hash: {:}", iter_hash);
        }
        randomx_calculate_hash_last(vm, hash.as_mut_ptr() as *mut std::ffi::c_void);

        let duration = start.elapsed().as_secs_f64();
        println!(
            "time elapsed: {:?} hashrate: {:?}",
            start.elapsed(),
            hashes_number as f64 / duration
        );
    }
}
