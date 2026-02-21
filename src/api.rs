//! 对外提供的 Rust 调用接口

use anyhow::bail;
use rand::RngCore;
use rand::rngs::OsRng;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::config::{
    PatternConfig, SearchConfig, SearchResult, SourceMode, TargetChain,
    parse_leading_zeros_condition, parse_pattern_condition, parse_prefix_condition,
    parse_suffix_condition,
};
use crate::kernel_loader::load_kernel_source;
use crate::opencl::{OpenCLContext, SearchKernel};

#[derive(Debug, Clone)]
pub enum SearchCondition {
    Prefix(String),
    Suffix(String),
    LeadingZeros(u32),
    Pattern(String),
}

#[derive(Debug, Clone)]
pub struct SearchRequest {
    pub condition: SearchCondition,
    pub threads: u32,
    pub work_group_size: usize,
    pub poll_interval: Duration,
    pub timeout: Option<Duration>,
    pub source_mode: SourceMode,
    pub multi_gpu: bool,
    pub base_seed: Option<[u8; 32]>,
}

impl SearchRequest {
    pub fn new(condition: SearchCondition) -> Self {
        Self {
            condition,
            threads: 1024,
            work_group_size: 128,
            poll_interval: Duration::from_millis(250),
            timeout: None,
            source_mode: SourceMode::MnemonicEntropy,
            multi_gpu: false,
            base_seed: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchResponse {
    pub found: bool,
    pub timed_out: bool,
    pub source_mode: SourceMode,
    pub result_seed: Option<[u8; 32]>,
    pub eth_address: Option<[u8; 20]>,
    pub found_by_thread: Option<u32>,
    pub found_device: Option<String>,
    pub elapsed: Duration,
    pub total_checked: u64,
    pub speed: f64,
}

impl SearchResponse {
    pub fn eth_address_hex(&self) -> Option<String> {
        self.eth_address.map(hex::encode)
    }

    pub fn result_seed_hex(&self) -> Option<String> {
        self.result_seed.map(hex::encode)
    }
}

struct SearchWorker {
    ctx: OpenCLContext,
    kernel: SearchKernel,
    threads: usize,
}

pub fn search(request: SearchRequest) -> anyhow::Result<SearchResponse> {
    if request.threads == 0 {
        bail!("threads must be greater than 0");
    }

    let (condition, pattern_config) = parse_condition(&request.condition)?;
    let base_seed = request.base_seed.unwrap_or_else(random_nonzero_seed);

    let contexts = if request.multi_gpu {
        let gpu_contexts = OpenCLContext::all_gpu_contexts()?;
        if gpu_contexts.is_empty() {
            vec![OpenCLContext::new()?]
        } else {
            gpu_contexts
        }
    } else {
        vec![OpenCLContext::new()?]
    };

    let thread_plan = split_threads(request.threads as usize, contexts.len());
    let kernel_source = load_kernel_source()?;

    let mut workers = Vec::new();
    for (idx, (ctx, threads)) in contexts
        .into_iter()
        .zip(thread_plan.into_iter())
        .enumerate()
    {
        if threads == 0 {
            continue;
        }

        let kernel = SearchKernel::new(&ctx, &kernel_source, threads)?;
        let worker_seed = seed_with_offset(base_seed, idx as u64 + 1);
        let config = if let Some(pattern) = pattern_config {
            SearchConfig::new_with_pattern(worker_seed, threads as u32, condition, pattern)
        } else {
            SearchConfig::new(worker_seed, threads as u32, condition)
        }
        .with_source_mode(request.source_mode)
        .with_target_chain(TargetChain::Ethereum);

        kernel.set_config(&config)?;
        workers.push(SearchWorker {
            ctx,
            kernel,
            threads,
        });
    }

    if workers.is_empty() {
        bail!("no available workers, try larger threads or disable multi_gpu");
    }

    for worker in &workers {
        worker
            .kernel
            .launch(worker.threads, Some(request.work_group_size))?;
    }

    let start_time = Instant::now();
    let mut found: Option<usize> = None;
    let mut result = SearchResult::default();

    loop {
        let timed_out = request
            .timeout
            .is_some_and(|timeout| start_time.elapsed() >= timeout);
        if timed_out {
            break;
        }

        for (idx, worker) in workers.iter_mut().enumerate() {
            if let Some(is_found) = worker.kernel.poll_found()? {
                if is_found {
                    found = Some(idx);
                    result = worker.kernel.read_result()?;
                    break;
                }
            }
        }

        if found.is_some() {
            break;
        }

        sleep(request.poll_interval);
    }

    if found.is_none() {
        for (idx, worker) in workers.iter().enumerate() {
            if let Ok(r) = worker.kernel.read_result() {
                if r.found != 0 {
                    found = Some(idx);
                    result = r;
                    break;
                }
            }
        }
    }

    let elapsed = start_time.elapsed();
    let timed_out = request.timeout.is_some_and(|timeout| elapsed >= timeout);
    let total_checked: u64 = workers
        .iter()
        .map(|w| w.kernel.read_total_checked(w.threads).unwrap_or(0))
        .sum();
    let total_checked = if total_checked > 0 {
        total_checked
    } else {
        result.total_checked()
    };
    let speed = if elapsed.as_secs_f64() > 0.0 {
        total_checked as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    if found.is_some() {
        sleep(Duration::from_millis(500));
    } else {
        for worker in &workers {
            let _ = worker.kernel.wait();
        }
    }

    let found_device = if let Some(idx) = found {
        Some(
            workers[idx]
                .ctx
                .device
                .name()
                .unwrap_or_else(|_| String::from("<unknown>")),
        )
    } else {
        None
    };

    let found_flag = found.is_some() && result.found != 0;
    Ok(SearchResponse {
        found: found_flag,
        timed_out: !found_flag && timed_out,
        source_mode: request.source_mode,
        result_seed: found_flag.then_some(result.result_seed),
        eth_address: found_flag.then_some(result.eth_address),
        found_by_thread: found_flag.then_some(result.found_by_thread),
        found_device,
        elapsed,
        total_checked,
        speed,
    })
}

fn parse_condition(condition: &SearchCondition) -> anyhow::Result<(u64, Option<PatternConfig>)> {
    match condition {
        SearchCondition::Prefix(value) => Ok((parse_prefix_condition(value)?, None)),
        SearchCondition::Suffix(value) => Ok((parse_suffix_condition(value)?, None)),
        SearchCondition::LeadingZeros(value) => Ok((parse_leading_zeros_condition(*value)?, None)),
        SearchCondition::Pattern(value) => {
            let (condition, pattern) = parse_pattern_condition(value)?;
            Ok((condition, Some(pattern)))
        }
    }
}

fn random_nonzero_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    if seed.iter().all(|&b| b == 0) {
        seed[31] = 1;
    }
    seed
}

fn seed_with_offset(base_seed: [u8; 32], offset: u64) -> [u8; 32] {
    let mut out = base_seed;
    let mut carry = offset;
    for b in out.iter_mut().rev() {
        let sum = (*b as u64) + (carry & 0xFF);
        *b = (sum & 0xFF) as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }
    out
}

fn split_threads(total_threads: usize, workers: usize) -> Vec<usize> {
    if workers == 0 {
        return Vec::new();
    }

    let base = total_threads / workers;
    let remainder = total_threads % workers;
    (0..workers)
        .map(|i| base + usize::from(i < remainder))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConditionType;

    #[test]
    fn test_request_defaults() {
        let req = SearchRequest::new(SearchCondition::Prefix(String::from("00")));
        assert_eq!(req.threads, 1024);
        assert_eq!(req.work_group_size, 128);
        assert_eq!(req.poll_interval, Duration::from_millis(250));
        assert!(req.timeout.is_none());
        assert_eq!(req.source_mode, SourceMode::MnemonicEntropy);
        assert!(!req.multi_gpu);
        assert!(req.base_seed.is_none());
    }

    #[test]
    fn test_parse_prefix_condition_via_api() {
        let (condition, pattern) =
            parse_condition(&SearchCondition::Prefix(String::from("8888"))).unwrap();
        assert!(pattern.is_none());
        let cond_type = (condition >> 48) & 0xFFFF;
        assert_eq!(cond_type, ConditionType::Prefix as u64);
    }
}
