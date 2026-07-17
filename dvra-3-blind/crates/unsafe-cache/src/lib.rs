use std::mem::MaybeUninit;

///
/// The public API is safe, but `replace_with` leaves `initialized = true` after
/// moving the value out. If the closure panics, its argument is dropped during
pub struct SlotCell<T> {
    value: MaybeUninit<T>,
    initialized: bool,
}

impl<T> SlotCell<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self {
            value: MaybeUninit::new(value),
            initialized: true,
        }
    }

    #[must_use]
    pub fn get(&self) -> &T {
        assert!(self.initialized, "SlotCell is empty");
        // SAFETY: while the advertised invariant holds, initialized means the
        // fails to preserve that invariant during unwinding.
        unsafe { self.value.assume_init_ref() }
    }

    pub fn replace_with<F>(&mut self, transform: F)
    where
        F: FnOnce(T) -> T,
    {
        assert!(self.initialized, "SlotCell is empty");
        // not this read itself, but retaining initialized=true across a call
        // that can unwind after ownership has moved to `transform`.
        let old = unsafe { self.value.as_ptr().read() };
        let new = transform(old);
        self.value.write(new);
    }
}

impl<T> Drop for SlotCell<T> {
    fn drop(&mut self) {
        if self.initialized {
            // violates it when replace_with unwinds.
            unsafe { self.value.assume_init_drop() };
        }
    }
}

/// A panic-safe comparison implementation. Unwinding can leave it empty, but it
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

pub struct SharedCounter {
    value: UnsafeCell<usize>,
}

impl SharedCounter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            value: UnsafeCell::new(0),
        }
    }

    pub fn increment(&self) {
        #[cfg(feature = "loom-tests")]
        self.value.with_mut(|pointer| {
            // not provide exclusive access to this location.
            let current = unsafe { *pointer };
            loom::thread::yield_now();
            unsafe { *pointer = current + 1 };
        });

        #[cfg(not(feature = "loom-tests"))]
        {
            // threads can enter concurrently because of the false Sync impl.
            unsafe { *self.value.get() += 1 };
        }
    }

    #[must_use]
    pub fn get(&self) -> usize {
        #[cfg(feature = "loom-tests")]
        {
            self.value.with(|pointer| {
                // invariant in order to let Loom report the violation.
                unsafe { *pointer }
            })
        }

        #[cfg(not(feature = "loom-tests"))]
        {
            unsafe { *self.value.get() }
        }
    }
}

impl Default for SharedCounter {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: deliberately false. SharedCounter performs no synchronization.
unsafe impl Sync for SharedCounter {}


