//! Deliberately unsound cache primitives used by the Miri and Loom labs.

use std::ptr;

/// A compact collection whose removal path is not unwind-safe.
#[derive(Debug)]
pub struct FragileVec<T> {
    items: Vec<T>,
}

impl<T> FragileVec<T> {
    #[must_use]
    pub fn from_vec(items: Vec<T>) -> Self {
        Self { items }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// Removes an item and hands ownership to a callback.
    ///
    /// If the callback unwinds, the vector length still includes the moved-out
    /// slot and `Drop` observes invalid state.
    pub fn remove_with<F>(&mut self, index: usize, callback: F)
    where
        F: FnOnce(T),
    {
        assert!(index < self.items.len(), "index out of bounds");
        let len = self.items.len();
        let base = self.items.as_mut_ptr();

        // SAFETY: The normal return path repairs the vector by shifting elements
        // and reducing its length. The intentional defect is that unwinding from
        // `callback` skips that repair.
        let value = unsafe { ptr::read(base.add(index)) };
        callback(value);
        // SAFETY: `index < len`; overlapping copy is required for a removal.
        unsafe {
            ptr::copy(base.add(index + 1), base.add(index), len - index - 1);
            self.items.set_len(len - 1);
        }
    }
}

#[cfg(feature = "loom-model")]
type CounterCell = loom::cell::UnsafeCell<usize>;
#[cfg(not(feature = "loom-model"))]
type CounterCell = std::cell::UnsafeCell<usize>;

/// Non-atomic shared counter with incorrect `Send` and `Sync` promises.
pub struct SharedCounter {
    value: CounterCell,
}

impl SharedCounter {
    #[must_use]
    pub fn new(value: usize) -> Self {
        Self {
            value: CounterCell::new(value),
        }
    }

    pub fn increment(&self) {
        #[cfg(feature = "loom-model")]
        self.value.with_mut(|pointer| {
            // SAFETY: The pointer is valid for the closure. The intentional
            // defect is allowing multiple threads to enter concurrently.
            unsafe {
                *pointer += 1;
            }
        });

        #[cfg(not(feature = "loom-model"))]
        // SAFETY: This safe public method supplies no synchronization. That is
        // the deliberate DVRA-009 defect.
        unsafe {
            *self.value.get() += 1;
        }
    }

    #[must_use]
    pub fn get(&self) -> usize {
        #[cfg(feature = "loom-model")]
        {
            self.value.with(|pointer| {
                // SAFETY: Loom tracks the read and reports conflicting access.
                unsafe { *pointer }
            })
        }

        #[cfg(not(feature = "loom-model"))]
        // SAFETY: Sequential callers can read the initialized value. Concurrent
        // callers make the public abstraction unsound.
        unsafe {
            *self.value.get()
        }
    }
}

// SAFETY: These are intentionally invalid promises for the concurrency lab.
unsafe impl Send for SharedCounter {}
// SAFETY: `increment` performs a non-atomic write through this shared reference.
unsafe impl Sync for SharedCounter {}

#[cfg(test)]
mod tests {
    use super::{FragileVec, SharedCounter};

    #[test]
    fn fragile_vec_normal_return_path_looks_correct() {
        let mut values = FragileVec::from_vec(vec!["one".to_owned(), "two".to_owned()]);
        values.remove_with(0, drop);
        assert_eq!(values.as_slice(), ["two"]);
    }

    #[test]
    fn shared_counter_looks_correct_sequentially() {
        #[cfg(feature = "loom-model")]
        loom::model(|| {
            let counter = SharedCounter::new(0);
            counter.increment();
            assert_eq!(counter.get(), 1);
        });

        #[cfg(not(feature = "loom-model"))]
        {
            let counter = SharedCounter::new(0);
            counter.increment();
            assert_eq!(counter.get(), 1);
        }
    }

    #[cfg(miri)]
    #[test]
    fn dvra_008_miri_detects_double_drop_after_callback_panic() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let mut values = FragileVec::from_vec(vec!["moved".to_owned()]);
        let _ = catch_unwind(AssertUnwindSafe(|| {
            values.remove_with(0, |_value| panic!("panic injection"));
        }));
        drop(values);
    }

    #[cfg(feature = "loom-model")]
    #[test]
    #[should_panic]
    fn dvra_009_loom_detects_concurrent_mutable_access() {
        loom::model(|| {
            let counter = loom::sync::Arc::new(SharedCounter::new(0));
            let left = loom::sync::Arc::clone(&counter);
            let right = loom::sync::Arc::clone(&counter);

            let left_thread = loom::thread::spawn(move || left.increment());
            let right_thread = loom::thread::spawn(move || right.increment());

            left_thread.join().expect("left thread");
            right_thread.join().expect("right thread");
            let _ = counter.get();
        });
    }
}
