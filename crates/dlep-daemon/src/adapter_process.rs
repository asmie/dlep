//! Support for the external adapter processes of the bundled commands.
//!
//! `dlep-router` and `dlep-modem` each run one configured program and exchange
//! JSON Lines with it: records are written to the adapter's standard input and
//! read from its standard output, while standard error is inherited for
//! logging. This module owns the process plumbing both commands share: line
//! framing, bounded writes, ambient-capability removal, failure supervision,
//! and the shutdown sequence. Message formats stay with each command.

use std::future::Future;
use std::io;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};

/// Longest accepted adapter output line, excluding the newline.
pub const MAX_LINE: usize = 64 * 1024;
/// Capacity of the queues between an adapter's pipes and its bridge.
pub const QUEUE_SIZE: usize = 64;
/// Deadline for writing one complete record to the adapter's input.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Grace period for the adapter to exit after its input closes.
pub const STOP_GRACE: Duration = Duration::from_secs(2);
/// Bytes of an offending adapter line kept in log and error messages.
const EXCERPT_LEN: usize = 256;

/// Lines read from an adapter's standard output. The reader stops after the
/// first error; the channel closes when the adapter closes its output.
pub type AdapterLines = mpsc::Receiver<Result<String, AdapterError>>;

/// Failures of an adapter process or its pipes. `label` names the adapter in
/// messages, for example `"router adapter"` or `"radio adapter"`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AdapterError {
    #[error("{label} line exceeds {MAX_LINE} bytes")]
    LineTooLong { label: &'static str },
    #[error("{label} output is not UTF-8")]
    NotUtf8 { label: &'static str },
    #[error("reading {label} output")]
    Read {
        label: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{label} closed its output")]
    OutputClosed { label: &'static str },
    #[error("{label} input stalled: it stopped reading for {}s", IO_TIMEOUT.as_secs())]
    InputStalled { label: &'static str },
    #[error("writing to {label}")]
    Write {
        label: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{label} input closed")]
    InputClosed { label: &'static str },
    #[error("{label} writer task failed")]
    WriterTask {
        label: &'static str,
        #[source]
        source: JoinError,
    },
    #[error("{label} exited with {status}")]
    Exited {
        label: &'static str,
        status: ExitStatus,
    },
    #[error("waiting for {label}")]
    Wait {
        label: &'static str,
        #[source]
        source: io::Error,
    },
}

/// The first 256 bytes of `line`, cut at a character boundary, for messages
/// that quote adapter output. Format the result with `{:?}` so control
/// characters and quotes in the line are escaped.
pub fn excerpt(line: &str) -> &str {
    if line.len() <= EXCERPT_LEN {
        return line;
    }
    let mut end = EXCERPT_LEN;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[..end]
}

/// Read newline-terminated UTF-8 lines into `lines`, without the newline.
/// Blank and whitespace-only lines are skipped. A final line without a newline
/// is delivered at end of input. A line longer than [`MAX_LINE`] bytes, a
/// non-UTF-8 line, or a read error is sent as the last item; allocation is
/// bounded by [`MAX_LINE`] plus one byte per line.
pub async fn read_lines<R: AsyncBufRead + Unpin>(
    mut reader: R,
    label: &'static str,
    lines: mpsc::Sender<Result<String, AdapterError>>,
) {
    loop {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .await;
        let result = match read {
            Ok(0) => return,
            Ok(_) if line.last() != Some(&b'\n') && line.len() > MAX_LINE => {
                Err(AdapterError::LineTooLong { label })
            }
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                String::from_utf8(line).map_err(|_| AdapterError::NotUtf8 { label })
            }
            Err(source) => Err(AdapterError::Read { label, source }),
        };
        if result.as_ref().is_ok_and(|text| text.trim().is_empty()) {
            continue;
        }
        let failed = result.is_err();
        if lines.send(result).await.is_err() || failed {
            return;
        }
    }
}

/// Write one record and its newline within [`IO_TIMEOUT`]. A record that the
/// adapter does not finish reading in time fails as stalled input.
pub async fn write_line(
    writer: &mut (impl AsyncWrite + Unpin),
    label: &'static str,
    mut line: String,
) -> Result<(), AdapterError> {
    line.push('\n');
    tokio::time::timeout(IO_TIMEOUT, writer.write_all(line.as_bytes()))
        .await
        .map_err(|_| AdapterError::InputStalled { label })?
        .map_err(|source| AdapterError::Write { label, source })
}

/// Write queued records in order until the queue closes or a write fails.
/// Returning drops the queue receiver, so later sends fail.
pub async fn write_queued(
    mut writer: impl AsyncWrite + Unpin,
    label: &'static str,
    mut queued: mpsc::Receiver<String>,
) -> Result<(), AdapterError> {
    while let Some(line) = queued.recv().await {
        write_line(&mut writer, label, line).await?;
    }
    Ok(())
}

/// A running adapter process with its output reader and input writer tasks.
/// Dropping it aborts both tasks and kills the process.
pub struct AdapterProcess {
    label: &'static str,
    child: Child,
    stdin: Option<ChildStdin>,
    reader: JoinHandle<()>,
    writer: Option<JoinHandle<Result<(), AdapterError>>>,
}

impl AdapterProcess {
    /// Start `command` with piped standard input and output, inherited
    /// standard error, and no ambient capabilities. The returned receiver
    /// yields the adapter's output lines as [`read_lines`] describes.
    pub fn spawn(
        label: &'static str,
        command: &Path,
        args: &[String],
    ) -> io::Result<(Self, AdapterLines)> {
        let mut command = Command::new(command);
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        drop_ambient_capabilities(&mut command);
        let mut child = command.spawn()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel(QUEUE_SIZE);
        let reader = tokio::spawn(read_lines(BufReader::new(stdout), label, tx));
        let process = Self {
            label,
            child,
            stdin,
            reader,
            writer: None,
        };
        Ok((process, lines))
    }

    /// Start the task that owns the adapter's standard input. Call once.
    /// The task should end when its own input closes, so [`Self::stop`] can
    /// close the adapter's input after the task flushed its last records.
    pub fn start_writer<F>(&mut self, writer: impl FnOnce(ChildStdin) -> F)
    where
        F: Future<Output = Result<(), AdapterError>> + Send + 'static,
    {
        let stdin = self.stdin.take().expect("writer started once");
        self.writer = Some(tokio::spawn(writer(stdin)));
    }

    /// Resolve when the adapter exits or its writer task ends; both are
    /// failures while the bridge runs. Cancel-safe.
    pub async fn failed(&mut self) -> AdapterError {
        let label = self.label;
        tokio::select! {
            status = self.child.wait() => match status {
                Ok(status) => AdapterError::Exited { label, status },
                Err(source) => AdapterError::Wait { label, source },
            },
            error = writer_outcome(label, &mut self.writer) => error,
        }
    }

    /// The writer task's own error, for a bridge whose record queue closed:
    /// the queue closes only when that task ends.
    pub async fn writer_error(&mut self) -> AdapterError {
        if self.writer.is_none() {
            return AdapterError::InputClosed { label: self.label };
        }
        writer_outcome(self.label, &mut self.writer).await
    }

    /// Close the adapter's input once the writer task finishes, then kill the
    /// adapter if it has not exited. The writer and the exit share one
    /// [`STOP_GRACE`] deadline. Close the writer's own queue first.
    pub async fn stop(mut self) {
        let deadline = tokio::time::Instant::now() + STOP_GRACE;
        self.stdin.take();
        if let Some(mut writer) = self.writer.take() {
            if tokio::time::timeout_at(deadline, &mut writer)
                .await
                .is_err()
            {
                writer.abort();
                let _ = writer.await;
            }
        }
        if tokio::time::timeout_at(deadline, self.child.wait())
            .await
            .is_err()
        {
            tracing::warn!(
                "{} did not exit after its input closed; killing it",
                self.label
            );
            let _ = self.child.kill().await;
        }
        self.reader.abort();
        let _ = (&mut self.reader).await;
    }
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        self.reader.abort();
        if let Some(writer) = &self.writer {
            writer.abort();
        }
        // `kill_on_drop` also covers failures during daemon startup.
    }
}

/// Wait for a started writer task and convert its outcome; never resolves
/// without one. The handle is cleared once the task has finished.
async fn writer_outcome(
    label: &'static str,
    writer: &mut Option<JoinHandle<Result<(), AdapterError>>>,
) -> AdapterError {
    let Some(handle) = writer else {
        return std::future::pending().await;
    };
    let result = handle.await;
    *writer = None;
    match result {
        Ok(Ok(())) => AdapterError::InputClosed { label },
        Ok(Err(error)) => error,
        Err(source) => AdapterError::WriterTask { label, source },
    }
}

/// The daemon's ambient capabilities (for example CAP_NET_RAW and
/// CAP_NET_BIND_SERVICE in the example units) would otherwise survive exec
/// into the adapter.
#[cfg(target_os = "linux")]
fn drop_ambient_capabilities(command: &mut Command) {
    use nix::libc;
    // SAFETY: the closure runs in the forked child before exec and makes only
    // an async-signal-safe prctl system call, reading errno on failure.
    unsafe {
        command.pre_exec(|| {
            let cleared = libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            let error = io::Error::last_os_error();
            // Kernels before 4.3 have no ambient set, so nothing is inherited.
            if cleared == -1 && error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_ambient_capabilities(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    const LABEL: &str = "test adapter";

    async fn read_all(input: &[u8]) -> Vec<Result<String, AdapterError>> {
        let (tx, mut rx) = mpsc::channel(QUEUE_SIZE);
        read_lines(input, LABEL, tx).await;
        let mut lines = Vec::new();
        while let Some(line) = rx.recv().await {
            lines.push(line);
        }
        lines
    }

    #[tokio::test]
    async fn line_of_exactly_max_line_bytes_is_accepted() {
        let input = [vec![b'x'; MAX_LINE], b"\nnext\n".to_vec()].concat();
        let lines = read_all(&input).await;
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].as_ref().unwrap().len(), MAX_LINE);
        assert_eq!(lines[1].as_ref().unwrap(), "next");
        // At end of input the limit applies without a newline too.
        let lines = read_all(&vec![b'x'; MAX_LINE]).await;
        assert_eq!(lines[0].as_ref().unwrap().len(), MAX_LINE);
    }

    #[tokio::test]
    async fn line_one_byte_over_max_line_is_rejected_and_ends_reading() {
        for input in [
            [vec![b'x'; MAX_LINE + 1], b"\nnext\n".to_vec()].concat(),
            vec![b'x'; MAX_LINE + 1],
        ] {
            let lines = read_all(&input).await;
            assert_eq!(lines.len(), 1);
            let error = lines[0].as_ref().unwrap_err();
            assert!(matches!(error, AdapterError::LineTooLong { .. }));
            assert_eq!(
                error.to_string(),
                format!("test adapter line exceeds {MAX_LINE} bytes")
            );
        }
    }

    #[tokio::test]
    async fn non_utf8_line_is_rejected_and_ends_reading() {
        let lines = read_all(b"ok\n\xff\xfe\nnext\n").await;
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].as_ref().unwrap(), "ok");
        assert_eq!(
            lines[1].as_ref().unwrap_err().to_string(),
            "test adapter output is not UTF-8"
        );
    }

    #[tokio::test]
    async fn final_line_without_newline_is_delivered_and_blank_lines_skipped() {
        let lines = read_all(b"\n  \t\nfirst\r\n\n\r\nlast").await;
        let lines: Vec<_> = lines.into_iter().map(Result::unwrap).collect();
        assert_eq!(lines, ["first\r", "last"]);
        assert!(read_all(b"").await.is_empty());
    }

    #[tokio::test]
    async fn reader_from_a_pipe_stops_when_the_receiver_closes() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(read_lines(BufReader::new(reader), LABEL, tx));
        writer.write_all(b"one\ntwo\n").await.unwrap();
        assert_eq!(rx.recv().await.unwrap().unwrap(), "one");
        drop(rx);
        writer.write_all(b"three\n").await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn excerpts_are_bounded_at_a_character_boundary() {
        assert_eq!(excerpt("short"), "short");
        let long = "é".repeat(EXCERPT_LEN);
        let cut = excerpt(&long);
        assert!(cut.len() <= EXCERPT_LEN && cut.len() > EXCERPT_LEN - 2);
        assert!(long.starts_with(cut));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_has_a_deadline_and_closes_the_queue() {
        let (input, _peer) = tokio::io::duplex(8);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        out.send("x".repeat(32)).await.unwrap();
        let start = Instant::now();
        let error = write_queued(input, LABEL, queued).await.unwrap_err();
        assert!(matches!(error, AdapterError::InputStalled { .. }));
        assert!(error.to_string().contains("test adapter input stalled"));
        assert_eq!(Instant::now() - start, IO_TIMEOUT);
        assert!(out.is_closed());
    }

    #[tokio::test]
    async fn writer_preserves_records_across_partial_writes_and_reports_broken_input() {
        let (input, mut peer) = tokio::io::duplex(4);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        for line in [r#"{"type":"first"}"#, r#"{"type":"second"}"#] {
            out.send(line.into()).await.unwrap();
        }
        drop(out);
        let mut received = String::new();
        let (result, read) = tokio::join!(
            write_queued(input, LABEL, queued),
            peer.read_to_string(&mut received)
        );
        result.unwrap();
        read.unwrap();
        assert_eq!(received, "{\"type\":\"first\"}\n{\"type\":\"second\"}\n");

        let (input, peer) = tokio::io::duplex(4);
        drop(peer);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        out.send("record".into()).await.unwrap();
        let error = write_queued(input, LABEL, queued).await.unwrap_err();
        assert!(error.to_string().contains("writing to test adapter"));
        assert!(out.is_closed());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writer_failure_is_reported_instead_of_a_closed_queue() {
        let (mut process, mut lines) = AdapterProcess::spawn(
            LABEL,
            Path::new("/bin/sh"),
            &["-c".into(), "exec 0<&-; echo ready; exec sleep 30".into()],
        )
        .unwrap();
        assert_eq!(lines.recv().await.unwrap().unwrap(), "ready");
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        process.start_writer(|stdin| write_queued(stdin, LABEL, queued));
        // The adapter closed its input, so a write fails with a broken pipe.
        let _ = out.send("record".into()).await;
        tokio::time::timeout(Duration::from_secs(5), out.closed())
            .await
            .unwrap();
        let error = process.writer_error().await;
        assert!(matches!(error, AdapterError::Write { .. }), "{error:?}");
        tokio::time::timeout(STOP_GRACE + Duration::from_secs(5), process.stop())
            .await
            .expect("stop kills an adapter that ignores input EOF");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn adapter_exit_is_reported_with_its_status() {
        let (mut process, mut lines) =
            AdapterProcess::spawn(LABEL, Path::new("/bin/sh"), &["-c".into(), "exit 3".into()])
                .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), process.failed())
            .await
            .unwrap();
        assert!(matches!(error, AdapterError::Exited { .. }), "{error:?}");
        assert!(error.to_string().starts_with("test adapter exited with"));
        assert!(lines.recv().await.is_none());
        process.stop().await;
    }
}
