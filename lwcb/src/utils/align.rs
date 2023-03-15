pub fn roundup(num: usize, r: usize) -> usize {
    ((num + (r - 1)) / r) * r
}

pub fn align8(offset: usize, elem_size: usize, elem_num: usize) -> usize {
    assert!(elem_size == 1 || elem_size == 2 || elem_size == 4 || elem_size == 8);
    roundup(offset, elem_size) + elem_size * elem_num
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align8() {
        assert!(align8(1, 8, 1) == 16);
    }
}
