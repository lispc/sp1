use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use std::fmt::Debug;
use std::marker::PhantomData;

use generic_array::GenericArray;
use num::BigUint;
use num::Zero;
use p3_air::AirBuilder;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_derive::AlignedBorrow;
use typenum::Unsigned;

use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::operations::field::field_op::FieldOpCols;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::Program;
use crate::runtime::Syscall;
use crate::runtime::SyscallCode;
use crate::syscall::precompiles::create_ec_add_event;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::field::NumLimbs;
use crate::utils::ec::field::NumWords;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::ec::AffinePoint;
use crate::utils::ec::CurveType;
use crate::utils::ec::EllipticCurve;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;

pub const fn num_weierstrass_add_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassAddAssignCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassAdd` that add two points on a Weierstrass curve.
///
/// Right now the number of limbs is assumed to be a constant, although this could be macro-ed or
/// made generic in the future.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassAddAssignCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub p_ptr: T,
    pub q_ptr: T,
    pub p_access: GenericArray<MemoryWriteCols<T>, P::WordsCurvePoint>,
    pub q_access: GenericArray<MemoryReadCols<T>, P::WordsCurvePoint>,
    pub(crate) slope_denominator: FieldOpCols<T, P>,
    pub(crate) slope_numerator: FieldOpCols<T, P>,
    pub(crate) slope: FieldOpCols<T, P>,
    pub(crate) slope_squared: FieldOpCols<T, P>,
    pub(crate) p_x_plus_q_x: FieldOpCols<T, P>,
    pub(crate) x3_ins: FieldOpCols<T, P>,
    pub(crate) p_x_minus_x: FieldOpCols<T, P>,
    pub(crate) y3_ins: FieldOpCols<T, P>,
    pub(crate) slope_times_p_x_minus_x: FieldOpCols<T, P>,
}

#[derive(Default)]
pub struct WeierstrassAddAssignChip<E> {
    _marker: PhantomData<E>,
}

impl<E: EllipticCurve> Syscall for WeierstrassAddAssignChip<E> {
    fn execute(&self, rt: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        let event = create_ec_add_event::<E>(rt, arg1, arg2);
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => rt.record_mut().secp256k1_add_events.push(event),
            CurveType::Bn254 => rt.record_mut().bn254_add_events.push(event),
            _ => panic!("Unsupported curve"),
        }
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

impl<E: EllipticCurve> WeierstrassAddAssignChip<E> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn populate_field_ops<F: PrimeField32>(
        cols: &mut WeierstrassAddAssignCols<F, E::BaseField>,
        p_x: BigUint,
        p_y: BigUint,
        q_x: BigUint,
        q_y: BigUint,
    ) {
        // This populates necessary field operations to calculate the addition of two points on a
        // Weierstrass curve.

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            let slope_numerator = cols
                .slope_numerator
                .populate(&q_y, &p_y, FieldOperation::Sub);

            let slope_denominator =
                cols.slope_denominator
                    .populate(&q_x, &p_x, FieldOperation::Sub);

            cols.slope
                .populate(&slope_numerator, &slope_denominator, FieldOperation::Div)
        };

        // x = slope * slope - (p.x + q.x).
        let x = {
            let slope_squared = cols
                .slope_squared
                .populate(&slope, &slope, FieldOperation::Mul);
            let p_x_plus_q_x = cols.p_x_plus_q_x.populate(&p_x, &q_x, FieldOperation::Add);
            cols.x3_ins
                .populate(&slope_squared, &p_x_plus_q_x, FieldOperation::Sub)
        };

        // y = slope * (p.x - x_3n) - p.y.
        {
            let p_x_minus_x = cols.p_x_minus_x.populate(&p_x, &x, FieldOperation::Sub);
            let slope_times_p_x_minus_x =
                cols.slope_times_p_x_minus_x
                    .populate(&slope, &p_x_minus_x, FieldOperation::Mul);
            cols.y3_ins
                .populate(&slope_times_p_x_minus_x, &p_y, FieldOperation::Sub);
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> MachineAir<F>
    for WeierstrassAddAssignChip<E>
where
    [(); num_weierstrass_add_cols::<E::BaseField>()]:,
{
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1AddAssign".to_string(),
            CurveType::Bn254 => "Bn254AddAssign".to_string(),
            _ => panic!("Unsupported curve"),
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // collects the events based on the curve type.
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => &input.secp256k1_add_events,
            CurveType::Bn254 => &input.bn254_add_events,
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();

        let mut new_byte_lookup_events = Vec::new();

        for i in 0..events.len() {
            let event = &events[i];
            let mut row = [F::zero(); num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();

            // Decode affine points.
            let p = &event.p;
            let q = &event.q;
            let p = AffinePoint::<E>::from_words_le(p);
            let (p_x, p_y) = (p.x, p.y);
            let q = AffinePoint::<E>::from_words_le(q);
            let (q_x, q_y) = (q.x, q.y);

            // Populate basic columns.
            cols.is_real = F::one();
            cols.shard = F::from_canonical_u32(event.shard);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.p_ptr = F::from_canonical_u32(event.p_ptr);
            cols.q_ptr = F::from_canonical_u32(event.q_ptr);

            Self::populate_field_ops(cols, p_x, p_y, q_x, q_y);

            // Populate the memory access columns.
            for i in 0..cols.q_access.len() {
                cols.q_access[i].populate(event.q_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.p_access.len() {
                cols.p_access[i].populate(event.p_memory_records[i], &mut new_byte_lookup_events);
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); num_weierstrass_add_cols::<E::BaseField>()];
            let cols: &mut WeierstrassAddAssignCols<F, E::BaseField> =
                row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            Self::populate_field_ops(cols, zero.clone(), zero.clone(), zero.clone(), zero);
            row
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            num_weierstrass_add_cols::<E::BaseField>(),
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => !shard.secp256k1_add_events.is_empty(),
            CurveType::Bn254 => !shard.bn254_add_events.is_empty(),
            _ => panic!("Unsupported curve"),
        }
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassAddAssignChip<E> {
    fn width(&self) -> usize {
        num_weierstrass_add_cols::<E::BaseField>()
    }
}

impl<AB, E: EllipticCurve> Air<AB> for WeierstrassAddAssignChip<E>
where
    AB: SP1AirBuilder,
    Limbs<AB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let row: &WeierstrassAddAssignCols<AB::Var, E::BaseField> = (*row).borrow();

        let num_words_field_element = <E::BaseField as NumLimbs>::Limbs::USIZE / 4;

        let p_x = limbs_from_prev_access(&row.p_access[0..num_words_field_element]);
        let p_y = limbs_from_prev_access(&row.p_access[num_words_field_element..]);

        let q_x = limbs_from_prev_access(&row.q_access[0..num_words_field_element]);
        let q_y = limbs_from_prev_access(&row.q_access[num_words_field_element..]);

        // slope = (q.y - p.y) / (q.x - p.x).
        let slope = {
            row.slope_numerator
                .eval::<AB, _, _>(builder, &q_y, &p_y, FieldOperation::Sub);

            row.slope_denominator
                .eval::<AB, _, _>(builder, &q_x, &p_x, FieldOperation::Sub);

            row.slope.eval::<AB, _, _>(
                builder,
                &row.slope_numerator.result,
                &row.slope_denominator.result,
                FieldOperation::Div,
            );

            &row.slope.result
        };

        // x = slope * slope - self.x - other.x.
        let x = {
            row.slope_squared
                .eval::<AB, _, _>(builder, slope, slope, FieldOperation::Mul);

            row.p_x_plus_q_x
                .eval::<AB, _, _>(builder, &p_x, &q_x, FieldOperation::Add);

            row.x3_ins.eval::<AB, _, _>(
                builder,
                &row.slope_squared.result,
                &row.p_x_plus_q_x.result,
                FieldOperation::Sub,
            );

            &row.x3_ins.result
        };

        // y = slope * (p.x - x_3n) - q.y.
        {
            row.p_x_minus_x
                .eval::<AB, _, _>(builder, &p_x, x, FieldOperation::Sub);

            row.slope_times_p_x_minus_x.eval::<AB, _, _>(
                builder,
                slope,
                &row.p_x_minus_x.result,
                FieldOperation::Mul,
            );

            row.y3_ins.eval::<AB, _, _>(
                builder,
                &row.slope_times_p_x_minus_x.result,
                &p_y,
                FieldOperation::Sub,
            );
        }

        // Constraint self.p_access.value = [self.x3_ins.result, self.y3_ins.result]. This is to
        // ensure that p_access is updated with the new value.
        for i in 0..E::BaseField::NB_LIMBS {
            builder
                .when(row.is_real)
                .assert_eq(row.x3_ins.result[i], row.p_access[i / 4].value()[i % 4]);
            builder
                .when(row.is_real)
                .assert_eq(row.y3_ins.result[i], row.p_access[8 + i / 4].value()[i % 4]);
        }

        builder.eval_memory_access_slice(
            row.shard,
            row.clk.into(),
            row.q_ptr,
            &row.q_access,
            row.is_real,
        );
        builder.eval_memory_access_slice(
            row.shard,
            row.clk + AB::F::from_canonical_u32(1), // We read p at +1 since p, q could be the same.
            row.p_ptr,
            &row.p_access,
            row.is_real,
        );

        // Fetch the syscall id for the curve type.
        let syscall_id_fe = match E::CURVE_TYPE {
            CurveType::Secp256k1 => {
                AB::F::from_canonical_u32(SyscallCode::SECP256K1_ADD.syscall_id())
            }
            CurveType::Bn254 => AB::F::from_canonical_u32(SyscallCode::BN254_ADD.syscall_id()),
            _ => panic!("Unsupported curve"),
        };

        builder.receive_syscall(
            row.shard,
            row.clk,
            syscall_id_fe,
            row.p_ptr,
            row.q_ptr,
            row.is_real,
        );
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        runtime::Program,
        utils::{
            run_test, setup_logger,
            tests::{BN254_ADD_ELF, BN254_MUL_ELF, SECP256K1_ADD_ELF, SECP256K1_MUL_ELF},
        },
    };

    #[test]
    fn test_secp256k1_add_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bn254_add_simple() {
        setup_logger();
        let program = Program::from(BN254_ADD_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_bn254_mul_simple() {
        setup_logger();
        let program = Program::from(BN254_MUL_ELF);
        run_test(program).unwrap();
    }

    #[test]
    fn test_secp256k1_mul_simple() {
        setup_logger();
        let program = Program::from(SECP256K1_MUL_ELF);
        run_test(program).unwrap();
    }
}
