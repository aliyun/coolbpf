/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
pub mod SafeReader {
    use byteorder::ByteOrder;
    use byteorder::LittleEndian;

    pub fn ptr(data: &Vec<u8>, offset: usize) -> u64 {
        if offset + 8 > data.len() {
            return 0;
        }
        LittleEndian::read_u64(&data[offset..])
    }

    pub fn u32(data: &Vec<u8>, offset: usize) -> u32 {
        if offset + 4 > data.len() {
            return 0;
        }
        LittleEndian::read_u32(&data[offset..])
    }

    pub fn u16(data: &Vec<u8>, offset: usize) -> u16 {
        if offset + 2 > data.len() {
            return 0;
        }
        LittleEndian::read_u16(&data[offset..])
    }

    pub fn u8(data: &Vec<u8>, offset: usize) -> u8 {
        if offset + 1 > data.len() {
            return 0;
        }
        data[offset]
    }
}
