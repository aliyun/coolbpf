/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use anyhow::Result;

// Represents a prefix with a Key and its corresponding Length for an LPM entry.
#[derive(Debug, Hash, PartialEq, PartialOrd, Ord, Eq, Clone, Copy)]
pub struct Prefix {
    pub key: u64,
    pub length: u32,
}

impl Prefix {
    fn new(key: u64, length: u32) -> Self {
        Prefix { key, length }
    }

    pub fn dummy() -> Self {
        Prefix::new(0, 64)
    }
}

fn get_rightmost_set_bit(x: u64) -> u64 {
    x & (!x + 1)
}

fn calculate_rmb(current_val: u64, end: u64) -> u64 {
    let mut rmb = get_rightmost_set_bit(current_val);
    while current_val + rmb > end {
        rmb >>= 1;
    }
    rmb
}

pub fn calculate_prefixes(start: u64, end: u64) -> Result<Vec<Prefix>> {
    let mut list_size = 0;
    let mut current_val = start;
    while current_val < end {
        current_val += calculate_rmb(current_val, end);
        list_size += 1;
    }

    let mut list = Vec::with_capacity(list_size);

    current_val = start;
    while current_val < end {
        let rmb = calculate_rmb(current_val, end);
        list.push(Prefix::new(current_val, 1 + (rmb.leading_zeros() as u32)));
        current_val += rmb;
    }

    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::calculate_prefixes;

    #[test]
    fn test_prefixes() {
        println!("{:?}", calculate_prefixes(10, 22));
    }
}
