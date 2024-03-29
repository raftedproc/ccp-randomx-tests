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
    Cache, RandomXError, RandomXFlags, RandomXVM, ResultHash,
};
use ccp_shared::types::{GlobalNonce, LocalNonce};
use ccp_shared::{types::CUID, RANDOMX_RESULT_SIZE};
use ccp_utils::hash::compute_global_nonce_cu;
use clap::Parser;
use rand::{thread_rng, Rng};

#[derive(Parser, Clone, Debug)]
struct Args {
    #[arg(long)]
    enable_msr: bool,
}

pub const TARGET_HASH_SIZE: usize = 32;
pub const BATCH_SIZE: usize = 2;

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

fn compute_randomx_hash(
    randomx_flags: RandomXFlags,
    global_nonce: &[u8],
    local_nonce: &[u8],
) -> Result<[u8; TARGET_HASH_SIZE], RandomXError> {
    let before_init = Instant::now();

    let cache = Cache::new(global_nonce, randomx_flags)?;
    let after_cache = before_init.elapsed();
    println!("compute_randomx_hash cache : {:?}", after_cache);

    let vm = RandomXVM::light(cache, randomx_flags)?;
    let res = vm.hash(local_nonce).into_slice();
    println!(
        "compute_randomx_hash hash : {:?}",
        before_init.elapsed() - after_cache
    );

    Ok(res)
}

// The current setup calculates one RandomX hash with given nonces.
fn prepare_and_run() {
    use rayon::prelude::*;
    use rayon::ThreadPoolBuilder;

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
    let mut rng = thread_rng();
    {
        let global_nonces = (0..BATCH_SIZE)
            .map(|_| {
                let length = rng.gen_range(BATCH_SIZE..BATCH_SIZE * 2);
                (0..length).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>()
            })
            .collect::<Vec<_>>();
        let local_nonces = (0..BATCH_SIZE)
            .map(|_| {
                let length = rng.gen_range(BATCH_SIZE..BATCH_SIZE * 2);
                (0..length).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>()
            })
            .collect::<Vec<_>>();

        let before_init = Instant::now();

        let pool = ThreadPoolBuilder::new()
            .num_threads(BATCH_SIZE)
            .build()
            .unwrap();
        println!(
            "run_randomx_batched pool threads: {}",
            pool.current_num_threads()
        );
        println!("after tp ctor: {:?}", before_init.elapsed(),);

        let randomx_flags = RandomXFlags::recommended();

        let before_init = Instant::now();
        while true {
            let before = before_init.elapsed();

            let _ = pool
                .install(|| -> Result<Vec<[u8; TARGET_HASH_SIZE]>, RandomXError> {
                    global_nonces
                        .par_iter()
                        .zip(local_nonces.par_iter())
                        .map(|(global_nonce, local_nonce)| {
                            compute_randomx_hash(randomx_flags, global_nonce, local_nonce)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap();
            let after = before_init.elapsed();
            println!("after the par iter: {:?}", after - before,);
        }
    }
}

fn main() {
    prepare_and_run();
}
