use tokio::sync::broadcast;

#[derive(Debug)]
pub(crate) struct Shutdown {
    is_shutdown: bool,
    notify: broadcast::Receiver<()>,
}

impl Shutdown {
    pub(crate) fn new(notify: broadcast::Receiver<()>) -> Shutdown {
        Shutdown { is_shutdown: false, notify }
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }

    /// Receives the shutdown notice, waiting if necessary.
    pub(crate) async fn recv(&mut self) {
        // If the shutdown signal has already been received, return immediately.
        if self.is_shutdown() {
            return;
        }

        // Cannot receive a 'lag error' as only one value is sent.
        let _ = self.notify.recv().await;

        // Remember that the shutdown signal has been received.
        self.is_shutdown = true;
    }
}