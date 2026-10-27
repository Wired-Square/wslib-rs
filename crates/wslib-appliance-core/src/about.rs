//! The seam where a product adds its own rows to Settings › About.

use std::future::Future;
use std::pin::Pin;

use futures_util::future::join_all;
use wslib_appliance_store::Store;
use wslib_appliance_types::about::{Fact, Subsystem};

/// What a product knows about itself, handed to `Server::about` or [`Mount::about`](crate::Mount::about).
pub trait About: Send + Sync + 'static {
    /// Read on every request, which waits for it: a probe that may hang is the
    /// implementation's to bound.
    fn about(&self, store: &Store) -> impl Future<Output = ProductAbout> + Send;
}

/// A product's facts, then one [`Subsystem`] per optional part; build it with [`new`](Self::new).
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ProductAbout {
    pub facts: Vec<Fact>,
    pub subsystems: Vec<Subsystem>,
}

impl ProductAbout {
    pub fn new(facts: Vec<Fact>, subsystems: Vec<Subsystem>) -> Self {
        Self { facts, subsystems }
    }
}

pub(crate) trait Erased: Send + Sync {
    fn about<'a>(
        &'a self,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = ProductAbout> + Send + 'a>>;
}

impl<A: About> Erased for A {
    fn about<'a>(
        &'a self,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = ProductAbout> + Send + 'a>> {
        Box::pin(About::about(self, store))
    }
}

pub(crate) struct Source {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) contributors: Vec<Box<dyn Erased>>,
}

impl Source {
    /// In the order the contributors were handed over.
    pub(crate) async fn rows(&self, store: &Store) -> ProductAbout {
        let mut all = ProductAbout::default();
        for rows in join_all(self.contributors.iter().map(|about| about.about(store))).await {
            all.facts.extend(rows.facts);
            all.subsystems.extend(rows.subsystems);
        }
        all
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Source")
            .field("product", &self.product)
            .field("version", &self.version)
            .field("contributors", &self.contributors.len())
            .finish()
    }
}
