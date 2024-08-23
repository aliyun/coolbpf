/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
use std::io::Read;
use std::io::{self};

// Unsigned5Decoder is a decoder for UNSIGNED5 based byte streams.
pub struct Unsigned5Decoder<R: Read> {
    r: R,
    x: u8,
}

impl<R: Read> Unsigned5Decoder<R> {
    pub fn new(reader: R, x: u8) -> Self {
        Unsigned5Decoder { r: reader, x }
    }

    fn get_byte(&mut self) -> Result<u8, io::Error> {
        let mut buf = [0u8; 1];
        self.r.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    pub fn get_uint(&mut self) -> Result<u32, io::Error> {
        const L: u8 = 192;
        let mut sum = 0u32;
        let mut shift = 0u32;
        let mut ch = self.get_byte()?;

        if ch < self.x {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("byte {:x} is in excluded range", ch),
            ));
        }
        sum = (ch - self.x) as u32;

        while ch >= L && shift < 30 {
            shift += 6;
            ch = self.get_byte()?;
            if ch < self.x {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("byte {:x} is in excluded range", ch),
                ));
            }
            sum = sum.wrapping_add(((ch - self.x) as u32) << shift);
        }
        Ok(sum)
    }

    fn get_signed(&mut self) -> Result<i32, io::Error> {
        let val = self.get_uint()?;
        Ok(((val >> 1) as i32) ^ -((val & 1) as i32))
    }

    pub fn decode_line_table_entry(
        &mut self,
        bci: &mut u32,
        line: &mut u32,
    ) -> Result<(), io::Error> {
        let b = self.get_byte()?;
        match b {
            0x00 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "End-of-Stream",
                ))
            }
            0xff => {
                let val_bci = self.get_signed()?;
                *bci = bci.wrapping_add(val_bci as u32);
                let val_line = self.get_signed()?;
                *line = line.wrapping_add(val_line as u32);
            }
            _ => {
                *bci = *bci + (b >> 3) as u32;
                *line = *line + (b & 7) as u32;
            }
        }
        Ok(())
    }

    pub fn map_byte_code_index_to_line(&mut self, bci: u32) -> u64 {
        let mut cur_bci = 0;
        let mut cur_line = 0;
        let mut best_bci = 0;
        let mut best_line = 0;

        loop {
            match self.decode_line_table_entry(&mut cur_bci, &mut cur_line) {
                Ok(_) => {
                    if cur_bci == bci {
                        return cur_line as u64;
                    }
                    if cur_bci >= best_bci && cur_bci < bci {
                        best_bci = cur_bci;
                        best_line = cur_line;
                    }
                }
                Err(_) => {
                    return best_line as u64;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use io::Cursor;
    #[test]
    fn test_java_line_numbers() {
        let bci_line = vec![
            (0, 478),
            (5, 479),
            (9, 480),
            (19, 481),
            (26, 482),
            (33, 483),
            (47, 490),
            (50, 485),
            (52, 486),
            (58, 490),
            (61, 488),
            (63, 489),
            (68, 491),
        ];

        let data = vec![
            255, 0, 252, 11, 41, 33, 81, 57, 57, 119, 255, 6, 9, 17, 52, 255, 6, 3, 17, 42, 0,
        ];
        let mut decoder = Unsigned5Decoder::new(Cursor::new(data), 0);

        let mut bci = 0;
        let mut line = 0;
        for expected in bci_line.iter() {
            assert!(decoder.decode_line_table_entry(&mut bci, &mut line).is_ok());
            assert_eq!(*expected, (bci, line));
        }

        assert!(
            matches!(decoder.decode_line_table_entry(&mut bci, &mut line), Err(e) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }
}
