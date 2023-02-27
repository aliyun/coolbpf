use chrono::{DateTime, Local, NaiveDateTime, Utc};
use std::fmt;

#[derive(Debug)]
pub struct TimeStr {
    dt: DateTime<Local>,
}

impl From<u64> for TimeStr {
    fn from(ns: u64) -> Self {
        let ndt = NaiveDateTime::from_timestamp_opt(
            (ns / 1_000_000_000) as i64,
            (ns % 1000_000_000) as u32,
        )
        .unwrap();
        let dt_utc: DateTime<Utc> = DateTime::from_utc(ndt, Utc);
        TimeStr { dt: dt_utc.into() }
    }
}

impl fmt::Display for TimeStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.dt)
    }
}
