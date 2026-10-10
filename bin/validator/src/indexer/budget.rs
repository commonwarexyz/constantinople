//! Bounds admitted upload memory while allowing an oversized block to make progress.

use super::{DURATION_BUCKETS, metric_i64};
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Gauge, Histogram, MetricsExt as _},
};
use std::{sync::Arc, time::Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

pub(super) const FINALIZED_UPLOAD_AMPLIFICATION: u64 = 8;
pub(super) const FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES: u64 = 64 * 1024;

#[derive(Clone)]
struct UploadBudgetMetrics {
    reserved_bytes: Gauge,
    admitted_bytes: Gauge,
    admitted: Gauge,
    reservation_held: Histogram,
}

impl UploadBudgetMetrics {
    fn new(context: &impl Metrics) -> Self {
        Self {
            reserved_bytes: context.gauge(
                "reserved_bytes",
                "Estimated finalized upload bytes currently reserved",
            ),
            admitted_bytes: context.gauge(
                "admitted_bytes",
                "Encoded payload bytes of admitted finalized uploads, the amplification base",
            ),
            admitted: context.gauge("admitted", "Finalized uploads currently admitted"),
            reservation_held: context.histogram(
                "reservation_held_duration",
                "Time finalized uploads hold an admission reservation (s)",
                DURATION_BUCKETS,
            ),
        }
    }
}

#[derive(Clone)]
pub(super) struct UploadBudget {
    permits: Arc<Semaphore>,
    total_units: u32,
    metrics: UploadBudgetMetrics,
}

impl UploadBudget {
    pub(super) fn new(context: &impl Metrics, configured_bytes: u64) -> Self {
        assert!(
            configured_bytes > 0,
            "finalized upload budget must be greater than zero"
        );
        let total_units = configured_bytes.div_ceil(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES);
        let total_units =
            u32::try_from(total_units).expect("finalized upload budget exceeds semaphore capacity");
        let total_units_usize = usize::try_from(total_units)
            .expect("finalized upload budget does not fit this platform");
        Self {
            permits: Arc::new(Semaphore::new(total_units_usize)),
            total_units,
            metrics: UploadBudgetMetrics::new(context),
        }
    }

    pub(super) fn charge(&self, encoded_bytes: u64) -> UploadCharge {
        let estimated_bytes = encoded_bytes.saturating_mul(FINALIZED_UPLOAD_AMPLIFICATION);
        let estimated_units = estimated_bytes
            .div_ceil(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES)
            .max(1);

        // An oversized upload reserves the whole budget so it runs alone.
        let permit_units = u32::try_from(estimated_units.min(u64::from(self.total_units)))
            .expect("admission charge is bounded by the budget");
        UploadCharge {
            encoded_bytes,
            estimated_bytes,
            permit_units,
        }
    }

    pub(super) fn try_reserve(&self, charge: UploadCharge) -> Option<UploadReservation> {
        match self
            .permits
            .clone()
            .try_acquire_many_owned(charge.permit_units)
        {
            Ok(permit) => Some(self.finish_reservation(charge, permit)),
            Err(TryAcquireError::NoPermits) => None,
            Err(TryAcquireError::Closed) => panic!("finalized upload budget closed"),
        }
    }

    pub(super) async fn reserve(&self, charge: UploadCharge) -> UploadReservation {
        let permit = self
            .permits
            .clone()
            .acquire_many_owned(charge.permit_units)
            .await
            .expect("finalized upload budget closed");
        self.finish_reservation(charge, permit)
    }

    fn finish_reservation(
        &self,
        charge: UploadCharge,
        permit: OwnedSemaphorePermit,
    ) -> UploadReservation {
        let estimated_bytes = metric_i64(charge.estimated_bytes);
        let encoded_bytes = metric_i64(charge.encoded_bytes);
        self.metrics.reserved_bytes.inc_by(estimated_bytes);
        self.metrics.admitted_bytes.inc_by(encoded_bytes);
        self.metrics.admitted.inc();
        UploadReservation {
            _permit: permit,
            metrics: self.metrics.clone(),
            estimated_bytes,
            encoded_bytes,
            started_at: Instant::now(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct UploadCharge {
    encoded_bytes: u64,
    estimated_bytes: u64,
    permit_units: u32,
}

pub(super) struct UploadReservation {
    _permit: OwnedSemaphorePermit,
    metrics: UploadBudgetMetrics,
    estimated_bytes: i64,
    encoded_bytes: i64,
    started_at: Instant,
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        self.metrics
            .reservation_held
            .observe(self.started_at.elapsed().as_secs_f64());
        self.metrics.reserved_bytes.dec_by(self.estimated_bytes);
        self.metrics.admitted_bytes.dec_by(self.encoded_bytes);
        self.metrics.admitted.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::{FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES, UploadBudget};
    use commonware_runtime::{Runner as _, Supervisor as _};

    #[test]
    fn upload_budget_blocks_until_reservations_drop() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let budget = UploadBudget::new(
                &context.child("upload_budget"),
                2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES,
            );
            let one_unit_encoded = FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8;
            let one_unit = budget.charge(one_unit_encoded);
            let two_units = budget.charge(one_unit_encoded + 1);

            let first = budget
                .try_reserve(one_unit)
                .expect("first charge fits budget");
            assert!(budget.try_reserve(two_units).is_none());
            assert_eq!(budget.metrics.admitted.get(), 1);

            drop(first);
            let second = budget
                .try_reserve(two_units)
                .expect("released capacity admits waiting charge");
            assert_eq!(budget.metrics.admitted.get(), 1);
            assert_eq!(
                budget.metrics.reserved_bytes.get(),
                i64::try_from(two_units.estimated_bytes).expect("test charge fits metric")
            );

            drop(second);
            assert_eq!(budget.metrics.reserved_bytes.get(), 0);
            assert_eq!(budget.metrics.admitted.get(), 0);
            assert!(budget.try_reserve(two_units).is_some());
        });
    }

    #[test]
    fn oversized_upload_reserves_the_entire_budget() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let configured_bytes = 2 * FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES;
            let budget = UploadBudget::new(&context.child("upload_budget"), configured_bytes);
            let regular_charge = budget.charge(FINALIZED_UPLOAD_BUDGET_QUANTUM_BYTES / 8);
            let oversized_charge = budget.charge(configured_bytes / 8 + 1);
            assert_eq!(oversized_charge.permit_units, budget.total_units);

            let regular = budget
                .try_reserve(regular_charge)
                .expect("regular charge fits budget");
            assert!(budget.try_reserve(oversized_charge).is_none());
            drop(regular);

            let oversized = budget
                .try_reserve(oversized_charge)
                .expect("oversized charge runs alone");
            assert!(budget.try_reserve(regular_charge).is_none());
            assert!(
                budget.metrics.reserved_bytes.get()
                    > i64::try_from(configured_bytes).expect("test budget fits metric")
            );

            drop(oversized);
            assert!(budget.try_reserve(regular_charge).is_some());
        });
    }
}
