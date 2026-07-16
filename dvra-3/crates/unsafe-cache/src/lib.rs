use std::mem::MaybeUninit;

/// A deliberately unsound container used for panic-safety review training.
///
/// The public API is safe, but `replace_with` leaves `initialized = true` after
/// moving the value out. If the closure panics, its argument is dropped during
/// unwinding and `PanicCell::drop` later drops the stale bytes again.
pub struct PanicCell<T> {
    value: MaybeUninit<T>,
    initialized: bool,
}

impl<T> PanicCell<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            value: MaybeUninit::new(value),
            initialized: true,
        }
    }

    #[must_use]
    pub fn get(&self) -> &T {
        assert!(self.initialized, "PanicCell is empty");
        // SAFETY: while the advertised invariant holds, initialized means the
        // storage contains a valid T. DVRA-004 demonstrates that replace_with
        // fails to preserve that invariant during unwinding.
        unsafe { self.value.assume_init_ref() }
    }

    pub fn replace_with<F>(&mut self, transform: F)
    where
        F: FnOnce(T) -> T,
    {
        assert!(self.initialized, "PanicCell is empty");
        // SAFETY: the value is initialized and uniquely borrowed. The bug is
        // not this read itself, but retaining initialized=true across a call
        // that can unwind after ownership has moved to `transform`.
        let old = unsafe { self.value.as_ptr().read() };
        let new = transform(old);
        self.value.write(new);
    }
}

impl<T> Drop for PanicCell<T> {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: this relies on the type invariant. DVRA-004 deliberately
            // violates it when replace_with unwinds.
            unsafe { self.value.assume_init_drop() };
        }
    }
}

/// A panic-safe comparison implementation. Unwinding can leave it empty, but it
/// cannot double-drop or expose uninitialized storage.
pub struct SafeCell<T> {
    value: Option<T>,
}

impl<T> SafeCell<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    #[must_use]
    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn replace_with<F>(&mut self, transform: F)
    where
        F: FnOnce(T) -> T,
    {
        let old = self.value.take().expect("SafeCell is empty");
        self.value = Some(transform(old));
    }
}

#[cfg(feature = "loom-tests")]
use loom::cell::UnsafeCell;
#[cfg(not(feature = "loom-tests"))]
use std::cell::UnsafeCell;

/// DVRA-005: an unsynchronized counter incorrectly declared `Sync`.
pub struct RacyCounter {
    value: UnsafeCell<usize>,
}

impl RacyCounter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: UnsafeCell::new(0),
        }
    }

    pub fn increment(&self) {
        #[cfg(feature = "loom-tests")]
        self.value.with_mut(|pointer| {
            // SAFETY: intentionally unsound. The false Sync implementation does
            // not provide exclusive access to this location.
            let current = unsafe { *pointer };
            loom::thread::yield_now();
            // SAFETY: same intentional DVRA-005 violation as above.
            unsafe { *pointer = current + 1 };
        });

        #[cfg(not(feature = "loom-tests"))]
        {
            // SAFETY: intentionally unsound for the training scenario. Multiple
            // threads can enter concurrently because of the false Sync impl.
            unsafe { *self.value.get() += 1 };
        }
    }

    #[must_use]
    pub fn get(&self) -> usize {
        #[cfg(feature = "loom-tests")]
        {
            self.value.with(|pointer| {
                // SAFETY: intentionally relies on the false synchronization
                // invariant in order to let Loom report the violation.
                unsafe { *pointer }
            })
        }

        #[cfg(not(feature = "loom-tests"))]
        {
            // SAFETY: intentionally unsound if another thread writes.
            unsafe { *self.value.get() }
        }
    }
}

impl Default for RacyCounter {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: deliberately false. RacyCounter performs no synchronization.
unsafe impl Sync for RacyCounter {}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{PanicCell, SafeCell};

    #[test]
    fn safe_cell_does_not_double_drop_after_panic() {
        let mut cell = SafeCell::new(String::from("value"));
        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.replace_with(|_old| panic!("injected panic"));
        }));
        assert!(result.is_err());
        assert!(cell.get().is_none());
    }

    #[test]
    #[ignore = "run under Miri; expected to report double free/use-after-free"]
    fn miri_finds_panic_safety_bug() {
        let mut cell = PanicCell::new(String::from("sensitive value"));
        let result = catch_unwind(AssertUnwindSafe(|| {
            cell.replace_with(|_old| panic!("injected panic"));
        }));
        assert!(result.is_err());
        drop(cell);
    }

    #[cfg(feature = "loom-tests")]
    #[test]
    #[should_panic]
    fn loom_detects_data_race() {
        loom::model(|| {
            let counter = loom::sync::Arc::new(super::RacyCounter::new());
            let left = loom::sync::Arc::clone(&counter);
            let right = loom::sync::Arc::clone(&counter);

            let first = loom::thread::spawn(move || left.increment());
            let second = loom::thread::spawn(move || right.increment());
            first.join().expect("first thread");
            second.join().expect("second thread");

            assert_eq!(counter.get(), 2);
        });
    }
}
