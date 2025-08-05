use std::{
    marker::PhantomPinned,
    ops::{Deref, DerefMut},
    pin::Pin,
};

use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
/// Secret structure automatically zeroing its content after use
///
/// # Security
///
/// ## Guidelines
///
/// This type cannot be manipulate without pinning it. Since we cannot
/// *escape* from a pin (since we are `!Unpin`), then all
/// objects of type [`Secret`] does not contains (yet) sensible value.
///
/// Thus all sensible [`Secret`]s live in a pin. This ensure that the sensible values
/// inside them cannot be moved in memory.
///
/// ## Why not `mut`ing `Pin<&mut [u8]>` instead of `&mut [u8]`
///
/// * `[u8]` is `Unpin` this does not protect anything
/// * `[u8]` seems to be necessary for cryptographic operations
///
/// # Cloning
///
/// Cloning is secure because zeroing will happen for each clone.
/// Copy is not possible since a destructor is defined ([`data`](struct@Secret) has a destructor)
///
/// # Access
///
/// Specific types can be designated as reader and updater of a [`Secret`] by implementing [`SecretReader`]
/// and [`SecretUpdater`].
pub struct Secret<Data: Zeroize> {
    /// Private field only accessible after pinning the secret
    data: Zeroizing<Data>,
    /// Force the type to be `!Unpin`, preventing escaping from a pin.
    /// This is necessary to ensure that a [`Secret`] with sensible value inside
    /// cannot live out of a pin.
    _pin: PhantomPinned,
}

impl<Data: Zeroize + Default> Secret<Data> {
    pub fn new() -> Self {
        Secret {
            data: Zeroizing::new(Data::default()),
            _pin: PhantomPinned,
        }
    }
}

impl<Data: Zeroize> Secret<Data> {
    fn _get(self: Pin<&Secret<Data>>) -> &Data {
        self.get_ref().data.deref()
    }

    fn _get_mut(self: Pin<&mut Secret<Data>>) -> &mut Data {
        // This is okay because `data` is *safe* (cannot produce *UB*) to move
        // More information on Rust [pin](https://doc.rust-lang.org/std/pin/index.html#choosing-pinning-not-to-be-structural-for-field) module
        unsafe { self.get_unchecked_mut().data.deref_mut() }
    }

    /// The only way to access self is by pinning it.
    pub fn read_with<A, Reader>(self: Pin<&Secret<Data>>, reader: &Reader) -> A
    where
        Reader: SecretReader<Data, A>,
        Data: Unsizeable,
    {
        reader.read(self._get().get_unsized())
    }

    /// The only way to access self is by pinning it.
    pub fn update_with<A, Updater>(self: Pin<&mut Secret<Data>>, updater: &Updater) -> A
    where
        Updater: SecretUpdater<Data, A>,
        Data: Unsizeable,
    {
        updater.update(self._get_mut().get_unsized_mut())
    }
}
/// This trait makes it possible to work on unsized types instead of
/// sized one. This prevent unattended copies of sensible data on the stack.
pub trait Unsizeable {
    type Unsized: ?Sized;
    fn get_unsized(&self) -> &Self::Unsized;
    fn get_unsized_mut(&mut self) -> &mut Self::Unsized;
}

impl<const N: usize> Unsizeable for [u8; N] {
    type Unsized = [u8];

    fn get_unsized(&self) -> &Self::Unsized {
        self
    }

    fn get_unsized_mut(&mut self) -> &mut Self::Unsized {
        self
    }
}

impl Unsizeable for String {
    type Unsized = str;

    fn get_unsized(&self) -> &Self::Unsized {
        self
    }

    fn get_unsized_mut(&mut self) -> &mut Self::Unsized {
        self
    }
}

impl<T> Unsizeable for Vec<T> {
    type Unsized = [T];

    fn get_unsized(&self) -> &Self::Unsized {
        self
    }

    fn get_unsized_mut(&mut self) -> &mut Self::Unsized {
        self
    }
}

/// A type reading a [`Secret`] must implement this trait.
///
/// Only the implementation of this trait and [`SecretUpdater`] is responsible of the secret privacy.
pub trait SecretReader<Data: Zeroize + Unsizeable, A> {
    /// # Secrets leak mitigation
    ///
    /// * Returned array is unsized in order to prevent
    ///   unwanted copy on the stack by dereferencing it.
    /// * `self` is *not* mutable, making it harder to leak secret
    ///
    /// # Leaks
    ///
    /// Secret can be extracted using globally effectfull reader. For instance
    ///
    /// * writing secret in a file or on the network
    /// * using interior mutability (for instance [`Cell`](https://doc.rust-lang.org/std/cell/struct.Cell.html)).
    ///
    /// # Security
    ///
    /// Cloning or moving returned array is *unsecure* because
    /// it could result in secret not being erased after use.
    fn read(&self, sec: &Data::Unsized) -> A;
}

impl<T, Data: Zeroize + Unsizeable, A> SecretReader<Data, A> for T
where
    T: Fn(&Data::Unsized) -> A,
{
    fn read(&self, sec: &Data::Unsized) -> A {
        self(sec)
    }
}

impl<T, Data: Zeroize + Unsizeable, A> SecretUpdater<Data, A> for T
where
    T: Fn(&mut Data::Unsized) -> A,
{
    fn update(&self, sec: &mut Data::Unsized) -> A {
        self(sec)
    }
}

/// A type updating a [`Secret`] must implement this trait.
///
/// Only the implementations of this trait and [`SecretReader`] is responsible of the secret privacy.
pub trait SecretUpdater<Data: Zeroize + Unsizeable, A> {
    /// # Secrets leak mitigation
    ///
    /// * Returned array is unsized in order to prevent
    ///   unwanted copy on the stack by dereferencing it.
    /// * `self` is *not* mutable, making it harder to leak secret
    ///
    /// # Leaks
    ///
    /// Secret can be extracted using globally effectfull reader. For instance
    ///
    /// * writing secret in a file or on the network
    /// * using interior mutability (for instance [`Cell`](https://doc.rust-lang.org/std/cell/struct.Cell.html)).
    ///
    /// # Security
    ///
    /// Cloning or moving returned array is *unsecure* because
    /// it could result in secret not being erased after use.
    fn update(&self, sec: &mut Data::Unsized) -> A;
}

#[cfg(test)]
mod test {

    use crate::api::Secret;

    #[test]
    fn test_if_secret_is_unpin() {
        trait CheckUnpin<const IS_UNPIN: bool> {
            fn is_unpin() -> bool {
                IS_UNPIN
            }
        }

        impl<T> CheckUnpin<false> for T {}
        impl<T: Unpin> CheckUnpin<true> for T {}

        type SecretByte = Secret<u8>;

        SecretByte::is_unpin(); // compile time error if Secret is unpin (because call to is_unpin is ambiguous)
    }
}
