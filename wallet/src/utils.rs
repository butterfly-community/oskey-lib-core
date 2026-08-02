use anyhow::anyhow;
use zeroize::Zeroize;

pub struct ByteVec<const N: usize> {
    inner: heapless::Vec<u8, N>,
}

impl<const N: usize> ByteVec<N> {
    pub fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), anyhow::Error> {
        self.inner.push(byte).map_err(|e| anyhow!(e))
    }

    pub fn extend(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.inner
            .extend_from_slice(data)
            .map_err(|_| anyhow!("Buffer full"))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl<const N: usize> Drop for ByteVec<N> {
    fn drop(&mut self) {
        for byte in self.inner.iter_mut() {
            byte.zeroize();
        }
    }
}
