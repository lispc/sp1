mod ec;
mod edwards;
mod fptower;
mod keccak256_permute;
mod sha256_compress;
mod sha256_extend;
mod uint256;

pub use ec::*;
pub use edwards::*;
pub use fptower::*;
use hashbrown::HashMap;
pub use keccak256_permute::*;
use serde::{Deserialize, Serialize};
pub use sha256_compress::*;
pub use sha256_extend::*;
use strum::{EnumIter, IntoEnumIterator};
pub use uint256::*;

use crate::syscalls::SyscallCode;

use super::MemoryLocalEvent;

#[derive(Clone, Debug, Serialize, Deserialize, EnumIter)]
/// Precompile event.  There should be one variant for every precompile syscall.
pub enum PrecompileEvent {
    /// Sha256 extend precompile event.
    ShaExtend(ShaExtendEvent),
    /// Sha256 compress precompile event.
    ShaCompress(ShaCompressEvent),
    /// Keccak256 permute precompile event.
    KeccakPermute(KeccakPermuteEvent),
    /// Edwards curve add precompile event.
    EdAdd(EllipticCurveAddEvent),
    /// Edwards curve decompress precompile event.
    EdDecompress(EdDecompressEvent),
    /// Secp256k1 curve add precompile event.
    Secp256k1Add(EllipticCurveAddEvent),
    /// Secp256k1 curve double precompile event.
    Secp256k1Double(EllipticCurveDoubleEvent),
    /// Secp256k1 curve decompress precompile event.
    Secp256k1Decompress(EllipticCurveDecompressEvent),
    /// K256 curve decompress precompile event.
    K256Decompress(EllipticCurveDecompressEvent),
    /// Bn254 curve add precompile event.
    Bn254Add(EllipticCurveAddEvent),
    /// Bn254 curve double precompile event.
    Bn254Double(EllipticCurveDoubleEvent),
    /// Bn254 base field operation precompile event.
    Bn254Fp(FpOpEvent),
    /// Grumpkin base field operation precompile event.
    GrumpkinFp(FpOpEvent),
    /// Bn254 quadratic field add/sub precompile event.
    Bn254Fp2AddSub(Fp2AddSubEvent),
    /// Bn254 quadratic field mul precompile event.
    Bn254Fp2Mul(Fp2MulEvent),
    /// Bls12-381 curve add precompile event.
    Bls12381Add(EllipticCurveAddEvent),
    /// Bls12-381 curve double precompile event.
    Bls12381Double(EllipticCurveDoubleEvent),
    /// Bls12-381 curve decompress precompile event.
    Bls12381Decompress(EllipticCurveDecompressEvent),
    /// Bls12-381 base field operation precompile event.
    Bls12381Fp(FpOpEvent),
    /// Bls12-381 quadratic field add/sub precompile event.
    Bls12381Fp2AddSub(Fp2AddSubEvent),
    /// Bls12-381 quadratic field mul precompile event.
    Bls12381Fp2Mul(Fp2MulEvent),
    /// Uint256 mul precompile event.
    Uint256Mul(Uint256MulEvent),
}

/// Trait to retrieve all the local memory events from a vec of precompile events.
pub trait PrecompileLocalMemory {
    /// Get an iterator of all the local memory events.
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent>;
}

impl PrecompileLocalMemory for Vec<PrecompileEvent> {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for event in self.iter() {
            match event {
                PrecompileEvent::ShaExtend(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::ShaCompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::KeccakPermute(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::EdDecompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Add(e)
                | PrecompileEvent::EdAdd(e)
                | PrecompileEvent::Bn254Add(e)
                | PrecompileEvent::Bls12381Add(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Double(e)
                | PrecompileEvent::Bn254Double(e)
                | PrecompileEvent::Bls12381Double(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Secp256k1Decompress(e)
                | PrecompileEvent::K256Decompress(e)
                | PrecompileEvent::Bls12381Decompress(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Uint256Mul(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp(e)
                | PrecompileEvent::Bn254Fp(e)
                | PrecompileEvent::GrumpkinFp(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp2AddSub(e) | PrecompileEvent::Bn254Fp2AddSub(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
                PrecompileEvent::Bls12381Fp2Mul(e) | PrecompileEvent::Bn254Fp2Mul(e) => {
                    iterators.push(e.local_mem_access.iter());
                }
            }
        }

        iterators.into_iter().flatten()
    }
}

/// A record of all the precompile events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrecompileEvents {
    events: HashMap<SyscallCode, Vec<PrecompileEvent>>,
}

impl Default for PrecompileEvents {
    fn default() -> Self {
        let mut events = HashMap::new();
        for syscall_code in SyscallCode::iter() {
            if syscall_code.should_send() == 1 {
                events.insert(syscall_code, Vec::new());
            }
        }

        Self { events }
    }
}

impl PrecompileEvents {
    pub(crate) fn append(&mut self, other: &mut PrecompileEvents) {
        for (syscall, events) in other.events.iter_mut() {
            if !events.is_empty() {
                self.events.entry(*syscall).or_default().append(events);
            }
        }
    }

    #[inline]
    /// Add a precompile event for a given syscall code.
    pub(crate) fn add_event(&mut self, syscall_code: SyscallCode, event: PrecompileEvent) {
        assert!(syscall_code.should_send() == 1);
        self.events.entry(syscall_code).or_default().push(event);
    }

    #[inline]
    /// Insert a vector of precompile events for a given syscall code.
    pub(crate) fn insert(&mut self, syscall_code: SyscallCode, events: Vec<PrecompileEvent>) {
        assert!(syscall_code.should_send() == 1);
        self.events.insert(syscall_code, events);
    }

    #[inline]
    pub(crate) fn into_iter(self) -> impl Iterator<Item = (SyscallCode, Vec<PrecompileEvent>)> {
        self.events.into_iter()
    }

    #[inline]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&SyscallCode, &Vec<PrecompileEvent>)> {
        self.events.iter()
    }

    #[inline]
    /// Get all the precompile events for a given syscall code.
    pub(crate) fn get_events(&self, syscall_code: SyscallCode) -> &Vec<PrecompileEvent> {
        assert!(syscall_code.should_send() == 1);
        &self.events[&syscall_code]
    }

    /// Get all the local events from all the precompile events.
    pub(crate) fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_mem_events());
        }

        iterators.into_iter().flatten()
    }
}
