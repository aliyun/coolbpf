use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Object, PerfBuffer, PerfBufferBuilder};

use crate::error::{Error, Result};

pub struct CoolBPF<S: Skel> {
    skel: S,
    rx: Option<crossbeam_channel::Receiver<(i32, Vec<u8>)>>,
}

impl<S: Skel> CoolBPF<S> {
    pub fn new(skel: S) -> Self {
        CoolBPF {
            skel,
            rx: None,
        }
    }

    pub fn tryfrom_builder<'a, O: OpenSkel<Output = S>, B: SkelBuilder<'a, Output = O>>(
        builder: B,
    ) -> Result<Self> {
        let openskel = builder.open()?;
        Self::tryfrom_openskel(openskel)
    }

    pub fn tryfrom_openskel<O: OpenSkel<Output = S>>(openskel: O) -> Result<Self> {
        let skel = openskel.load()?;
        Self::tryfrom_skel(skel)
    }

    pub fn tryfrom_skel(mut skel: S) -> Result<Self> {
        skel.attach()?;
        Ok(CoolBPF::new(skel))
    }

    pub fn open_perf<T: AsRef<str>>(&mut self, name: T) -> Result<()> {
        let (tx, rx) = crossbeam_channel::unbounded();
        self.rx = Some(rx);
        let handle_event = move |cpu: i32, data: &[u8]| {
            tx.send((cpu, data.to_vec())).unwrap();
        };

        let perf = PerfBufferBuilder::new(self.skel.object_mut().map_mut(name).unwrap())
            .sample_cb(handle_event)
            .lost_cb(handle_lost_events)
            .build()?;

        std::thread::spawn(move || loop {
            perf.poll(std::time::Duration::from_millis(200)).unwrap();
        });

        Ok(())
    }

    pub fn perf_recv(&mut self) -> Result<(i32, Vec<u8>)> {
        if let Some(rx) = &self.rx {
            return Ok(rx.recv()?);
        }

        Err(Error::PerfBufferNotExist)
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    log::warn!("Lost {count} events on CPU {cpu}");
}

#[cfg(test)]
mod tests {
    use super::*;

}
