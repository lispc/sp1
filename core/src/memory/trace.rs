use p3_field::PrimeField32;

use super::{MemoryAccessCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols};
use crate::bytes::ByteLookupEvent;
use crate::bytes::ByteOpcode::{U16Range, U8Range};
use crate::runtime::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord};

impl<F: PrimeField32> MemoryWriteCols<F> {
    pub fn populate(
        &mut self,
        record: MemoryWriteRecord,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            shard: record.shard,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            shard: record.prev_shard,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_blu_events);
    }
}

impl<F: PrimeField32> MemoryReadCols<F> {
    pub fn populate(
        &mut self,
        record: MemoryReadRecord,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            shard: record.shard,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            shard: record.prev_shard,
            timestamp: record.prev_timestamp,
        };
        self.access
            .populate_access(current_record, prev_record, new_blu_events);
    }
}

impl<F: PrimeField32> MemoryReadWriteCols<F> {
    pub fn populate(
        &mut self,
        record: MemoryRecordEnum,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        match record {
            MemoryRecordEnum::Read(read_record) => {
                self.populate_read(read_record, new_blu_events);
            }
            MemoryRecordEnum::Write(write_record) => {
                self.populate_write(write_record, new_blu_events);
            }
        }
    }

    pub fn populate_write(
        &mut self,
        record: MemoryWriteRecord,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            shard: record.shard,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            shard: record.prev_shard,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_blu_events);
    }

    pub fn populate_read(
        &mut self,
        record: MemoryReadRecord,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            shard: record.shard,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            shard: record.prev_shard,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(current_record, prev_record, new_blu_events);
    }
}

impl<F: PrimeField32> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        new_blu_events: &mut Vec<ByteLookupEvent>,
    ) {
        self.value = current_record.value.into();

        self.prev_shard = F::from_canonical_u32(prev_record.shard);
        self.prev_clk = F::from_canonical_u32(prev_record.timestamp);

        // Fill columns used for verifying current memory access time value is greater than previous's.
        let use_clk_comparison = prev_record.shard == current_record.shard;
        self.compare_clk = F::from_bool(use_clk_comparison);
        let prev_time_value = if use_clk_comparison {
            prev_record.timestamp
        } else {
            prev_record.shard
        };
        let current_time_value = if use_clk_comparison {
            current_record.timestamp
        } else {
            current_record.shard
        };

        let diff_minus_one = current_time_value - prev_time_value - 1;
        let diff_16bit_limb = diff_minus_one & 0xffff;
        self.diff_16bit_limb = F::from_canonical_u32(diff_16bit_limb);
        let diff_8bit_limb = (diff_minus_one >> 16) & 0xff;
        self.diff_8bit_limb = F::from_canonical_u32(diff_8bit_limb);

        let shard = current_record.shard;

        // Add a byte table lookup with the 16Range op.
        new_blu_events.push(ByteLookupEvent::new(
            shard,
            U16Range,
            diff_16bit_limb,
            0,
            0,
            0,
        ));

        // Add a byte table lookup with the U8Range op.
        new_blu_events.push(ByteLookupEvent::new(
            shard,
            U8Range,
            0,
            0,
            0,
            diff_8bit_limb,
        ));
    }
}
