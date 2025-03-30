use std::fs;
use std::sync::atomic::AtomicU8;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time;

use chrono::SecondsFormat;
use chrono::Utc;
use ocl::builders::DeviceSpecifier;
use ocl::builders::ProgramBuilder;
use ocl::flags::MemFlags;
use ocl::Buffer;
use ocl::Platform;
use ocl::ProQue;
use ocl::Result;
use rand::RngCore;
use rayon::prelude::*;
use regex::Regex;

use crate::handler::handle_keypair;
use crate::Args;

#[derive(Clone, Copy)]
struct GpuOptions {
    pub platform_idx: usize,
    pub device_idx: usize,
    pub threads: usize,
    pub local_work_size: Option<usize>,
    pub global_work_size: Option<usize>,
}

struct Gpu {
    kernel: ocl::Kernel,
    results: Buffer<u8>,
    keys: Buffer<u8>,
}

impl Gpu {
    pub fn new(opts: GpuOptions) -> Result<Gpu> {
        let mut prog_bldr = ProgramBuilder::new();
        prog_bldr
            .src(include_str!("../kernel/sha512.cl"))
            .src(include_str!("../kernel/curve25519-constants.cl"))
            .src(include_str!("../kernel/curve25519-constants2.cl"))
            .src(include_str!("../kernel/curve25519.cl"))
            .src(include_str!("../kernel/entry.cl"));
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err("No OpenCL platforms exist (check your drivers and OpenCL setup)".into());
        }
        if opts.platform_idx >= platforms.len() {
            return Err(format!(
                "Platform index {} too large (max {})",
                opts.platform_idx,
                platforms.len() - 1
            )
            .into());
        }
        let pro_que = ProQue::builder()
            .prog_bldr(prog_bldr)
            .platform(platforms[opts.platform_idx])
            .device(DeviceSpecifier::Indices(vec![opts.device_idx]))
            .dims(32 * opts.threads)
            .build()?;

        let device = pro_que.device();
        eprintln!("Initializing GPU {} {}", device.vendor()?, device.name()?);

        let results = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().write_only().host_read_only())
            .build()?;
        let keys = pro_que
            .buffer_builder::<u8>()
            .flags(MemFlags::new().read_only().host_write_only())
            .build()?;

        let kernel = {
            let mut kernel_builder = pro_que.kernel_builder("generate_pubkey");
            kernel_builder
                .global_work_size(opts.threads)
                .arg(&results)
                .arg(&keys);
            if let Some(local_work_size) = opts.local_work_size {
                kernel_builder.local_work_size(local_work_size);
            }
            if let Some(global_work_size) = opts.global_work_size {
                kernel_builder.global_work_size(global_work_size);
            }
            kernel_builder.build()?
        };

        Ok(Gpu {
            kernel,
            results,
            keys,
        })
    }

    pub fn compute(&mut self) -> Result<()> {
        unsafe {
            self.kernel.enq()?;
        }
        Ok(())
    }

    pub fn read_keys(&mut self, results: &mut [u8]) -> Result<()> {
        self.results.read(results).enq()?;
        Ok(())
    }

    pub fn write_seeds(&mut self, keys: &[u8]) -> Result<()> {
        self.keys.write(keys).enq()?;
        Ok(())
    }
}

pub fn run_opencl(
    args: &Args,
    regexes: &[String],
    compiled_regexes: Vec<Regex>,
    csv_file: &Option<Mutex<fs::File>>,
) {
    let pubkeys = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let next_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));
    let current_seeds = Arc::new(Mutex::new(vec![0; 32 * args.threads]));

    let mut gpu = Gpu::new(GpuOptions {
        platform_idx: args.platform_idx,
        device_idx: args.device_idx,
        threads: args.threads,
        local_work_size: args.local_work_size,
        global_work_size: args.global_work_size,
    })
    .unwrap();

    let (start_write_compute_tx, start_write_compute_rx) = mpsc::channel::<()>();
    let (seeds_wrote_tx, seeds_wrote_rx) = mpsc::channel::<()>();
    let (start_keys_read_tx, start_keys_read_rx) = mpsc::channel::<()>();
    let (keys_read_tx, pubkeys_read_rx) = mpsc::channel::<()>();

    let _gpu_thread = {
        let seeds = next_seeds.clone();
        let pubkeys = pubkeys.clone();
        thread::spawn(move || loop {
            keys_read_tx.send(()).unwrap();
            start_write_compute_rx.recv().unwrap();

            gpu.write_seeds(&seeds.lock().unwrap()).unwrap();
            seeds_wrote_tx.send(()).unwrap();

            gpu.compute().unwrap();

            start_keys_read_rx.recv().unwrap();
            gpu.read_keys(&mut pubkeys.lock().unwrap()).unwrap();
        })
    };

    let max_leading_zeros: Vec<AtomicU8> = (0..(compiled_regexes.len()))
        .map(|_| AtomicU8::new(0))
        .collect();
    let mut first_run = true;

    gen_random_seeds(&mut next_seeds.lock().unwrap());

    let mut start = time::Instant::now();
    let mut iters = 0u64;

    loop {
        start_write_compute_tx.send(()).unwrap();

        pubkeys_read_rx.recv().unwrap();
        if !first_run {
            handle_keypairs(
                &current_seeds.lock().unwrap(),
                &pubkeys.lock().unwrap(),
                regexes,
                &compiled_regexes,
                &max_leading_zeros,
                csv_file,
            );
        }
        start_keys_read_tx.send(()).unwrap();

        gen_random_seeds(&mut current_seeds.lock().unwrap());
        seeds_wrote_rx.recv().unwrap();
        std::mem::swap(
            &mut *current_seeds.lock().unwrap(),
            &mut *next_seeds.lock().unwrap(),
        );

        iters += args.threads as u64;
        let elapsed = start.elapsed();
        if !first_run && elapsed.as_secs() >= args.log_interval {
            let hashrate = iters as f64 / elapsed.as_secs_f64() / 1_000_000.0;
            eprintln!(
                "{} Hashrate: {:.2} MH/s",
                Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                hashrate
            );
            start = time::Instant::now();
            iters = 0;
        }
        if first_run {
            first_run = false;
        }
    }
}

fn handle_keypairs(
    seeds: &[u8],
    pubkeys: &[u8],
    regex_sources: &[String],
    regexes: &[Regex],
    max_leading_zeros: &[AtomicU8],
    csv_file: &Option<Mutex<fs::File>>,
) {
    pubkeys
        .par_chunks_exact(32)
        .zip(seeds.par_chunks_exact(32))
        .for_each(|(pk, seed)| {
            handle_keypair(
                seed,
                pk,
                regex_sources,
                regexes,
                max_leading_zeros,
                csv_file,
            )
        });
}

fn gen_random_seeds(seeds: &mut [u8]) {
    seeds.par_chunks_exact_mut(128 * 1024).for_each(|seed| {
        rand::thread_rng().fill_bytes(seed);
    })
}
