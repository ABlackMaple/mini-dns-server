use std::{collections::{BTreeSet, HashMap}, sync::Arc, time::Duration};

use tokio::{sync::{Notify, RwLock}, time::{self, Instant}};
use tracing::{debug, error, info, warn};

use crate::dns::types::{RecordType, ResourceRecord};

mod hosts;

/// The `DbGuard` struct is used to manage the database connection and ensure that
/// the database is properly closed when the guard is dropped.
/// It contains a reference to the `Db` struct, which represents the database itself.
#[derive(Debug)]
pub(crate) struct DbGuard {
    db: Db,
}

/// The 'Db' struct represents the shared database.
#[derive(Debug, Clone)]
pub(crate) struct Db {
    shared: Arc<Shared>,
}

/// The `Shared` struct contains the shared state of the database.
/// It includes a read-write lock for the state, a notify object for background tasks,
/// and the maximum size of the database.
#[derive(Debug)]
struct Shared {
    state: RwLock<State>,
    background_task: Notify,
    max_size: usize,
}

/// The `State` struct represents the current state of the database.
/// It includes a hash map of entries, a set of expirations, and a shutdown flag.
/// The hash map stores the entries in the database, where the key is a `Key`
/// and the value is an `Entry`.
/// The set of expirations stores the expiration times of the entries.
/// The shutdown flag indicates whether the database is shutting down.
#[derive(Debug)]
struct State {
    entries: HashMap<Key, Entry>,
    expirations: BTreeSet<(Instant, Key)>,
    shutdown: bool,
}

/// The `Key` struct represents a key in the database.
/// It includes a name (domain) and a record type.
/// The name is a string that represents the domain name,
/// and the record type is an enum that represents the type of DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    name: String,
    rtype: RecordType,
}

/// The `Entry` struct represents an entry in the database.
/// It includes a vector of `ResourceRecord` objects and an optional expiration time.
/// The vector of `ResourceRecord` objects represents the DNS records associated with the key,
/// and the expiration time is an `Option<Instant>` that indicates when the entry should expire.
/// If the expiration time is `None`, the entry does not expire.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    data: Vec<ResourceRecord>,
    expires_at: Option<Instant>,
}

impl Drop for DbGuard {
    /// The `drop` method is called when the `DbGuard` is dropped.
    /// It shuts down the background task and logs a message.
    fn drop(&mut self) {
        let db = self.db.clone();
        tokio::spawn(async move {
            db.shutdown_purge_task().await;
        });
        debug!("DbGuard dropped, shutting down background task");
    }
}

impl DbGuard {
    /// Creates a new `DbGuard` instance.
    /// It initializes the database and loads hosts into the database if a path is provided.
    /// # Arguments
    /// - `db_path`: An optional string that represents the path to the hosts file.
    /// - `max_size`: The maximum size of the database.
    /// # Returns
    /// - `DbGuard`: A new instance of `DbGuard`.
    pub(crate) async fn new(db_path: Option<String>, max_size: usize) -> DbGuard {
        let db_guard = DbGuard { db: Db::new(max_size) };

        if let Some(path) = db_path {
            let ttl = u32::MAX;
            if let Err(e) = db_guard.db.load_hosts_into_db(&path, ttl as u32).await {
                error!(cause = ?e, "failed to load hosts into db");
            }
        }

        db_guard
    }
    /// Returns a reference to the database.
    pub(crate) fn db(&self) -> Db {
        self.db.clone()
    }
}

impl Db {
    /// Creates a new `Db` instance.
    /// It initializes the shared state and starts a background task to purge expired entries.
    /// # Arguments
    /// - `max_size`: The maximum size of the database.
    /// # Returns
    /// - `Db`: A new instance of `Db`.
    pub(crate) fn new(max_size: usize) -> Db {
        let shared = Arc::new(Shared {
            state: RwLock::new(State {
                entries: HashMap::new(),
                expirations: BTreeSet::new(),
                shutdown: false,
            }),
            max_size,
            background_task: Notify::new(),
        });
        tokio::spawn(purge_expired_tasks(shared.clone()));
        Db { shared }
    }

    async fn load_hosts_into_db(&self, path: &str, ttl: u32) -> crate::Result<u32> {
        let count = hosts::load_hosts_into_db(&self, path, ttl).await?;
        Ok(count)
    }

    /// Get the Entry from the Db by ref Key.
    /// # Arguments
    /// - `key`: A reference to a `Key` object.
    /// # Returns
    /// - `Option<Entry>`: An optional `Entry` object.
    /// If the entry is found, it returns `Some(Entry)`, otherwise it returns `None`.
    pub(crate) async fn get(&self, key: &Key) -> Option<Entry> {

        let state = self.shared.state.read().await;
        let result = state.entries.get(key).map(|entry| entry.clone());
        if result.is_some() {
            info!(domain = %key.name, rtype = %key.rtype, "cache hit");
        } else {
            debug!(domain = %key.name, rtype = %key.rtype, "cache miss");
        }
        result
    }

    /// Insert a new entry into the database.
    /// # Arguments
    /// - `key`: A `Key` object that represents the key for the entry.
    /// - `value`: A vector of `ResourceRecord` objects that represents the data for the entry.
    /// - `expire`: An optional `Duration` that represents the expiration time for the entry.
    pub(crate) async fn insert(&self, key: Key, value: Vec<ResourceRecord>, expire: Option<Duration>) {
        let mut key = key;
        // Normalize the key name to lowercase
        // This is important for DNS queries, as they are case-insensitive.
        key.name = key.name.to_lowercase();
        let mut state = self.shared.state.write().await;

        let mut notify = false;

        // 
        let expires_at = expire.map(|duration| {
            let when = Instant::now() + duration;

            notify = state
                .next_expiration()
                .map(|expiration| expiration > when)
                .unwrap_or(true);

            let max_size = self.shared.max_size;
            // Check if the cache is over 90% full
            if max_size.saturating_sub(state.entries.len()) < max_size / 10 {
                // If the cache is over max_size, notify the background task
                notify |= state.entries.len() > self.shared.max_size;

                warn!(
                    current_size = state.entries.len(),
                    max_size = self.shared.max_size,
                    "cache size over 90%"
                );
            }

            when
        });

        
        debug!("inserting key: '{:?}', value: '{:?}'", key, value);
        // Insert the new entry into the database
        let prev = state.entries.insert(
            key.clone(), 
            Entry { data: value, expires_at },
        );

        // If the entry already existed, remove it from the expirations set
        if let Some(prev) = prev {
            if let Some(when) = prev.expires_at {
                state.expirations.remove(&(when, key.clone()));
                debug!("removing key: '{:?}' from expirations", key);
            }
        }

        // If the entry is new and ttl exists, add it to the expirations set
        if let Some(when) = expires_at {
            debug!("adding key: '{:?}' to expirations", key);
            state.expirations.insert((when, key));
        }

        // Drop 'state' becasuse background_task may use it.
        drop(state);
        if notify {
            self.shared.background_task.notify_one();
        }

    }

    async fn shutdown_purge_task(&self) {
        let mut state = self.shared.state.write().await;
        state.shutdown = true;
        drop(state);
        self.shared.background_task.notify_one();
    }
}

impl Shared {
    async fn is_shutdown(&self) -> bool {
        self.state.read().await.shutdown
    }

    /// Purge expired keys from the database.
    /// # Returns
    /// - `Option<Instant>`: An optional `Instant` object that represents the next expiration time.
    /// If there are no expired keys, it returns `None`.
    async fn purge_expired_keys(&self) -> Option<Instant> {
        let mut state = self.state.write().await;

        // Check if the server is shutdown.
        if state.shutdown {
            return None
        }

        // This is needed to make the borrow checker happy. In short, `lock()`
        // returns a `MutexGuard` and not a `&mut State`. The borrow checker is
        // not able to see "through" the mutex guard and determine that it is
        // safe to access both `state.expirations` and `state.entries` mutably,
        // so we get a "real" mutable reference to `State` outside of the loop.// 
        let state = &mut *state;

        let now = Instant::now();

        while let Some(&(when, ref key)) = state.expirations.iter().next() {
            if when > now && state.entries.len() < self.max_size{
                return Some(when)
            }
            state.entries.remove(key);
            debug!("purging key: '{:?}', current cache count: {}", key, state.entries.len());
            state.expirations.remove(&(when, key.clone()));
        }

        None
    }
}

impl State {
    fn next_expiration(&self) -> Option<Instant> {
        self.expirations
            .iter()
            .next()
            .map(|expiration| expiration.0)
    }
}

/// Routine executed by the background task.
///
/// Wait to be notified. On notification, purge any expired keys from the shared
/// state handle. If `shutdown` is set, terminate the task.
async fn purge_expired_tasks(shared: Arc<Shared>) {
    while !shared.is_shutdown().await {
        if let Some(when) = shared.purge_expired_keys().await {
            // Wait until the next key expires **or** until the background task
            // is notified. If the task is notified, then it must reload its
            // state as new keys have been set to expire early. This is done by
            // looping.
            tokio::select! {
                _ = time::sleep_until(when) => {}
                _ = shared.background_task.notified() => {}
            }
        } else {
            // There are no keys expiring in the future. Wait until the task is
            // notified.
            shared.background_task.notified().await;
        }
    }

    debug!("Purge background task shut down")
}

impl Key {
    pub fn new(name: String, rtype: RecordType) -> Self {
        Key { name, rtype }
    }
    
}

impl Entry {
    pub(crate) fn to_answer(mut self) -> Vec<ResourceRecord> {
        self.data.iter_mut().for_each(|record| {
            if let Some(expire) = self.expires_at {
                record.ttl = (expire - Instant::now()).as_secs() as u32;
            }
        });
        self.data
    }
}