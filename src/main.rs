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
    RandomXFlags,
};
use clap::Parser;

#[derive(Parser, Clone, Debug)]
struct Args {
    #[arg(long)]
    enable_msr: bool,
}

fn main() {
    let Args { enable_msr } = Args::parse();
    let flags = RandomXFlags::recommended_full_mem();
    println!("{:?}", flags);
    let block_template: Vec<u8> = vec![
        0x07, 0x07, 0xf7, 0xa4, 0xf0, 0xd6, 0x05, 0xb3, 0x03, 0x26, 0x08, 0x16, 0xba, 0x3f, 0x10,
        0x90, 0x2e, 0x1a, 0x14, 0x5a, 0xc5, 0xfa, 0xd3, 0xaa, 0x3a, 0xf6, 0xea, 0x44, 0xc1, 0x18,
        0x69, 0xdc, 0x4f, 0x85, 0x3f, 0x00, 0x2b, 0x2e, 0xea, 0x00, 0x00, 0x00, 0x00, 0x77, 0xb2,
        0x06, 0xa0, 0x2c, 0xa5, 0xb1, 0xd4, 0xce, 0x6b, 0xbf, 0xdf, 0x0a, 0xca, 0xc3, 0x8b, 0xde,
        0xd3, 0x4d, 0x2d, 0xcd, 0xee, 0xf9, 0x5c, 0xd2, 0x0c, 0xef, 0xc1, 0x2f, 0x61, 0xd5, 0x61,
        0x09,
    ];
    let global_nonce = vec![1, 2, 3, 4, 5, 6, 7];
    let mut hash: Vec<u64> = vec![0; 4];
    let hashes_number = 100000;
    unsafe {
        let before_init = Instant::now();

        let cache = randomx_alloc_cache(flags.bits());
        randomx_init_cache(
            cache,
            global_nonce.as_ptr() as *const std::ffi::c_void,
            global_nonce.len(),
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
            block_template.as_ptr() as *const std::ffi::c_void,
            block_template.len(),
        );
        for _ in 0..=hashes_number {
            randomx_calculate_hash_next(
                vm,
                block_template.as_ptr() as *const std::ffi::c_void,
                block_template.len(),
                hash.as_mut_ptr() as *mut std::ffi::c_void,
            )
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
