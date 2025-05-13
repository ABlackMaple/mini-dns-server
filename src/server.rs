use std::{io::Cursor, net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, select, sync::{broadcast, mpsc, Semaphore}};
use tracing::{error, info, warn};

use crate::{db::{Db, DbGuard}, dns::{frame::Frame, processor::Processor}, shutdown::Shutdown};

/// Run the DNS server
/// # Arguments
/// - `socket`: The socket to use for the server
/// - `shutdown`: A future that will be resolved when the server should shut down
/// - `max_connections`: The maximum number of connections to allow
/// - `max_cache_size`: The maximum size of the cache
/// - `upstream`: The upstream DNS server to use
/// - 'db_path': The path to the local hosts file
pub async fn run(socket: UdpSocket, shutdown: impl Future, max_connections: usize, max_cache_size: usize, upstream: Vec<SocketAddr>, db_path: Option<String>) {
    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    let mut server = Server {
        socket: Arc::new(socket),
        upstream,
        db_holder: DbGuard::new(db_path, max_cache_size).await,
        limit_connnection: Arc::new(Semaphore::new(max_connections)),
        notify_shutdown,
        shutdown_complete_tx,
        max_connections,
    };

    // Concurrently run the server and listen for the 'shutdown' signal.
    select! {
        res = server.run() => {
            // If an error received here, accepting connections from the socket failed and the server is
            // giving up and shutting down.
            if let Err(e) = res {
                error!(cause = ?e, "fail to recv");
            }
        },
        _ = shutdown => {
            info!("shutting down");
        },
    }

    let Server{notify_shutdown, shutdown_complete_tx, ..} = server;

    // Notify the server to shut down.
    drop(notify_shutdown);
    // Drop final 'Sender' so the 'Receiver' below can complete.
    drop(shutdown_complete_tx);

    // Wait for the server to complete its shutdown process.
    let _ = shutdown_complete_rx.recv().await;
}

#[derive(Debug)]
struct Server {
    socket: Arc<UdpSocket>,
    upstream: Vec<SocketAddr>,
    db_holder: DbGuard,
    limit_connnection: Arc<Semaphore>,
    notify_shutdown: broadcast::Sender<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
    max_connections: usize,
}

#[derive(Debug)]
struct Handle {
    buffer: Vec<u8>,
    db: Db,
    processor: Processor,
    shutdown: Shutdown,
    _shutdown_complete: mpsc::Sender<()>,
}

impl Server {
    /// Accept incoming connections and process them.
    async fn run(&mut self) -> crate::Result<()> {
        info!("start accepting data");
        loop {
            // Wait for a permit to be available before processing the next connection.
            let permit = self
                .limit_connnection
                .clone()
                .acquire_owned()
                .await
                .unwrap();
            let available = self.limit_connnection.available_permits();
            if available < self.max_connections / 10 {
                warn!(available = %available, max = %self.max_connections, "low available connection");
            }
            let mut buffer = vec![0; 512];
            // Receive data from the socket.
            // The buffer is resized to the actual length of the data received.
            let (len, addr) = self.socket.recv_from(&mut buffer).await?;
            buffer.truncate(len);
            
            info!(client = %addr, "recv data");

            // Create a new handle to process the received data.
            let mut handle = Handle {
                buffer,
                db: self.db_holder.db(),
                processor: Processor::new(addr, self.upstream.first().unwrap().clone(), self.socket.clone()),
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
                _shutdown_complete: self.shutdown_complete_tx.clone(),
            };

            // Spawn a new task to handle the connection.
            tokio::spawn(async move {
                if let Err(e) = handle.run().await {
                    error!(cause = ?e, "fail to process connection");
                }
                // Return the permit to the semaphore.
                drop(permit);
            });

        }
    }
}

impl Handle {
    /// Process the received data and apply the DNS request.
    async fn run(&mut self) -> crate::Result<()> {
        let mut cursor = Cursor::new(&self.buffer[..]);
        let maybe_frame = tokio::select! {
            _ = self.shutdown.recv() => {
                return Ok(());
            },
            res = self.processor.parse_message(&mut cursor) => {
                res?
            },
        };
        if let Frame::Request(msg) = maybe_frame {
            self.processor.apply(&self.db, &msg).await?;
        } else {
            return Err(format!("Unexpected response: {:?}", maybe_frame).into());
        }

        Ok(())
    }
}