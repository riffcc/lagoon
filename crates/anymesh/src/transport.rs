//! AnymeshStream — a TCP stream that supports socket migration.
//!
//! Wraps a `tokio::net::TcpStream` and implements `AsyncRead + AsyncWrite`,
//! which satisfies Lagoon's `RelayTransport` trait. Zero overhead for normal
//! I/O — the only addition is the ability to freeze the connection for
//! migration via TCP_REPAIR.

use std::io;

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::repair::{self, SocketMigration};
use crate::Error;

/// A TCP stream that can be frozen and migrated to another node.
///
/// Implements `AsyncRead + AsyncWrite + Unpin + Send`, which satisfies
/// Lagoon's `RelayTransport` blanket impl.
pub struct AnymeshStream {
    inner: TcpStream,
    migration_source: Option<SocketMigration>,
}

impl AnymeshStream {
    /// Wrap a normal `TcpStream`.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            migration_source: None,
        }
    }

    /// Create from a restored migration.
    pub fn from_migration(stream: TcpStream, state: SocketMigration) -> Self {
        Self {
            inner: stream,
            migration_source: Some(state),
        }
    }

    /// Whether this stream was restored from a migration.
    pub fn is_migrated(&self) -> bool {
        self.migration_source.is_some()
    }

    /// The migration state this stream was restored from, if any.
    pub fn migration_source(&self) -> Option<&SocketMigration> {
        self.migration_source.as_ref()
    }

    /// Freeze this stream for migration. Consumes self.
    ///
    /// The socket is closed without sending RST/FIN. The returned
    /// `SocketMigration` can be serialized and sent to another node
    /// for restoration.
    ///
    /// Requires `CAP_NET_ADMIN`.
    pub fn freeze(self) -> Result<SocketMigration, Error> {
        let std_stream = self.inner.into_std().map_err(Error::Freeze)?;
        let state = repair::freeze(&std_stream)?;
        // Close the fd while in repair mode (no RST/FIN).
        repair::close_silent(std_stream);
        Ok(state)
    }

    /// Restore a stream from a migrated socket state.
    ///
    /// Requires `CAP_NET_ADMIN`.
    pub fn restore(state: &SocketMigration) -> Result<Self, Error> {
        let std_stream = repair::restore(state)?;
        std_stream
            .set_nonblocking(true)
            .map_err(Error::Restore)?;
        let stream = TcpStream::from_std(std_stream).map_err(Error::Restore)?;
        Ok(Self::from_migration(stream, state.clone()))
    }

    /// Get a reference to the inner `TcpStream`.
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }

    /// Unwrap into the inner `TcpStream`.
    pub fn into_inner(self) -> TcpStream {
        self.inner
    }
}

impl AsyncRead for AnymeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AnymeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for AnymeshStream {}

// SAFETY: TcpStream is Send.
unsafe impl Send for AnymeshStream {}
