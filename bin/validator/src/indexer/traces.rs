//! Keeps capture traces bounded while linking durable work across tasks.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tracing::{Span, field, info_span};

// A stalled Store must not turn the durable queue into unbounded telemetry state.
const MAX_QUEUED_TRACES: usize = 4096;

pub(super) fn block_span(height: u64, origin: &'static str) -> Span {
    info_span!(
        parent: None,
        "indexer.block",
        height,
        origin,
        block_digest = field::Empty,
        position = field::Empty,
        payload_bytes = field::Empty,
        outcome = field::Empty,
    )
}

struct QueuedTrace {
    root: Span,
    _wait: Span,
}

#[derive(Clone, Default)]
pub(super) struct CaptureTraces {
    queued: Arc<Mutex<BTreeMap<u64, QueuedTrace>>>,
}

impl CaptureTraces {
    pub(super) fn register(&self, height: u64, root: Span) {
        if root.is_disabled() {
            return;
        }
        let mut queued = self.queued.lock().expect("trace registry lock poisoned");
        if queued.len() == MAX_QUEUED_TRACES {
            let (_, evicted) = queued.pop_first().expect("trace registry is full");
            evicted.root.record("outcome", "context_evicted");
        }

        // Registration precedes enqueue because the consumer can read before its sender resumes.
        let wait = info_span!(parent: &root, "indexer.queue.enqueue_to_read", height);
        let replaced = queued.insert(height, QueuedTrace { root, _wait: wait });
        assert!(replaced.is_none(), "capture trace registered twice");
    }

    pub(super) fn take(&self, height: u64, replay: bool) -> Span {
        let captured = self
            .queued
            .lock()
            .expect("trace registry lock poisoned")
            .remove(&height);
        match captured {
            Some(captured) => captured.root,
            None => block_span(height, if replay { "replay" } else { "continuation" }),
        }
    }
}

#[cfg(test)]
mod testing {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tracing::{
        Id, Subscriber,
        field::{Field, Visit},
        span::{Attributes, Record},
    };
    use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

    #[derive(Clone, Debug)]
    pub(super) struct RecordedSpan {
        pub(super) name: &'static str,
        pub(super) parent: Option<u64>,
        pub(super) closed: bool,
        pub(super) fields: BTreeMap<String, String>,
    }

    struct Fields<'a>(&'a mut BTreeMap<String, String>);

    impl Visit for Fields<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }
    }

    #[derive(Clone, Default)]
    pub(super) struct Capture(Arc<Mutex<BTreeMap<u64, RecordedSpan>>>);

    impl Capture {
        pub(super) fn spans(&self) -> BTreeMap<u64, RecordedSpan> {
            self.0.lock().unwrap().clone()
        }
    }

    impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Capture {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, context: Context<'_, S>) {
            let parent = attrs.parent().map(Id::into_u64).or_else(|| {
                attrs
                    .is_contextual()
                    .then(|| context.current_span().id().map(Id::into_u64))
                    .flatten()
            });
            let mut fields = BTreeMap::new();
            attrs.record(&mut Fields(&mut fields));
            self.0.lock().unwrap().insert(
                id.into_u64(),
                RecordedSpan {
                    name: attrs.metadata().name(),
                    parent,
                    closed: false,
                    fields,
                },
            );
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
            values.record(&mut Fields(
                &mut self
                    .0
                    .lock()
                    .unwrap()
                    .get_mut(&id.into_u64())
                    .unwrap()
                    .fields,
            ));
        }

        fn on_close(&self, id: Id, _: Context<'_, S>) {
            self.0
                .lock()
                .unwrap()
                .get_mut(&id.into_u64())
                .unwrap()
                .closed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureTraces, MAX_QUEUED_TRACES, block_span, testing::Capture};
    use tracing_subscriber::prelude::*;

    #[test]
    fn queue_handoff_preserves_parent_and_closes_wait() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            let traces = CaptureTraces::default();
            let root = block_span(7, "finalization");
            let id = root.id().unwrap().into_u64();
            traces.register(7, root);
            assert!(!capture.spans()[&id].closed);

            let root = traces.take(7, false);
            assert_eq!(root.id().unwrap().into_u64(), id);
            let spans = capture.spans();
            let wait = spans
                .values()
                .find(|span| span.name == "indexer.queue.enqueue_to_read")
                .unwrap();
            assert_eq!(wait.parent, Some(id));
            assert!(wait.closed);
            assert!(!spans[&id].closed);
            drop(root);
            assert!(capture.spans()[&id].closed);
        });
    }

    #[test]
    fn backlog_contexts_are_bounded_and_missing_roots_are_labeled() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        tracing::subscriber::with_default(subscriber, || {
            let traces = CaptureTraces::default();
            let first = block_span(1, "finalization");
            let id = first.id().unwrap().into_u64();
            traces.register(1, first.clone());
            for height in 2..=MAX_QUEUED_TRACES as u64 + 1 {
                traces.register(height, block_span(height, "finalization"));
            }
            assert_eq!(traces.queued.lock().unwrap().len(), MAX_QUEUED_TRACES);
            let spans = capture.spans();
            assert!(!spans[&id].closed);
            assert_eq!(spans[&id].fields["outcome"], "context_evicted");
            drop(first);
            assert!(capture.spans()[&id].closed);

            let continuation = traces.take(1, false);
            let replay = traces.take(0, true);
            let spans = capture.spans();
            assert_eq!(
                spans[&continuation.id().unwrap().into_u64()].fields["origin"],
                "continuation"
            );
            assert_eq!(
                spans[&replay.id().unwrap().into_u64()].fields["origin"],
                "replay"
            );
        });
    }
}
