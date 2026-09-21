//! Test-only loopback HTTP stub. Both backends accept plain `http://` for
//! loopback hosts (see `is_localhost_http` / `service_urls`), so the real
//! reqwest clients can be pointed at this server and the whole protocol
//! path — request shape, status handling, EncString decryption — runs
//! unchanged. Keeps the default suite offline: nothing leaves the machine.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub(crate) struct StubServer {
    /// `http://127.0.0.1:<port>` — pass as `server_endpoint` / `server_url`.
    pub(crate) base_url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for StubServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StubServer {
    /// Serve `(path, status, body)` routes; any other path answers 404.
    /// A 3xx status makes `body` the `Location` header instead: the response
    /// is then a redirect, which is what a client's redirect policy is judged
    /// against.
    pub(crate) async fn start(routes: Vec<(String, u16, String)>) -> Self {
        let routes: Arc<HashMap<String, (u16, String)>> = Arc::new(
            routes
                .into_iter()
                .map(|(path, status, body)| (path, (status, body)))
                .collect(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, routes.clone()));
            }
        });
        Self { base_url, task }
    }
}

async fn serve(mut stream: tokio::net::TcpStream, routes: Arc<HashMap<String, (u16, String)>>) {
    // Drain the whole request before replying: answering mid-body would make
    // the client see a broken pipe on its own write instead of the response.
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    let path = request
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let (status, body) = routes
        .get(path)
        .cloned()
        .unwrap_or_else(|| (404, "{}".to_string()));
    let (location, body) = if (300..400).contains(&status) {
        (format!("Location: {body}\r\n"), String::new())
    } else {
        (String::new(), body)
    };
    let response = format!(
        "HTTP/1.1 {status} STATUS\r\n{location}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Read headers, then exactly `Content-Length` more bytes. Returns the head.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(head)
}

/// A unique, existing temp directory for one test. Removed on drop.
pub(crate) struct TmpDir(pub(crate) std::path::PathBuf);

impl TmpDir {
    pub(crate) fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "tapwarden-test-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub(crate) fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Throwaway Ed25519 key generated for tests only — never used anywhere real.
pub(crate) const TEST_ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCchMvXfB6t0MgCDWTEX3BFd3ryJu7qUK+i+YOxqMDgkQAAAJgrZITGK2SE
xgAAAAtzc2gtZWQyNTUxOQAAACCchMvXfB6t0MgCDWTEX3BFd3ryJu7qUK+i+YOxqMDgkQ
AAAEAm+GqINSVahnMAQlWg2nq5Hv32qMRXAMb2+tLQm/aQvZyEy9d8Hq3QyAINZMRfcEV3
evIm7upQr6L5g7GowOCRAAAAE3VuaXQtdGVzdEB0YXB3YXJkZW4BAg==
-----END OPENSSH PRIVATE KEY-----
";

/// Throwaway RSA key generated for tests only — never used anywhere real.
/// Exists so the "Ed25519 only" gate has a non-Ed25519 key to refuse; RSA
/// because `ssh-key` only decodes ed25519, RSA and DSA with our features.
pub(crate) const TEST_RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAqajZtXNyitPQ3jX8+Ylb+KQGAfO0sfVT6/RON5YrbGB0s3YdTsIG
JJKxbR6fOp2Ci9BS6F5iyUs+9cnnNooSQHn+fTTrVCcJAW+Ck/KatoNrHi9G5fB+880Ksx
lc2MEvOIrDortwVsqF0mlIyXHQytIl6gqkCyWNzDOiIyz6rishLTXi2o98JjfCaTuFxttc
mrfRAQ/J3K7nc/3wz5Qyzj0ISxFl7lkBYCDRtcH5hdSSEBFKInneb1fQlLRTGJnDMlTPwg
kZr4gGYM392fubuYYGu2d417DGVvNm5G3Kag8UHiPxNKMPIOPUWFVvUDwuE0ucHZ8JNv4M
sUhe0iAt5wAAA8iEqBcrhKgXKwAAAAdzc2gtcnNhAAABAQCpqNm1c3KK09DeNfz5iVv4pA
YB87Sx9VPr9E43litsYHSzdh1OwgYkkrFtHp86nYKL0FLoXmLJSz71yec2ihJAef59NOtU
JwkBb4KT8pq2g2seL0bl8H7zzQqzGVzYwS84isOiu3BWyoXSaUjJcdDK0iXqCqQLJY3MM6
IjLPquKyEtNeLaj3wmN8JpO4XG21yat9EBD8ncrudz/fDPlDLOPQhLEWXuWQFgING1wfmF
1JIQEUoied5vV9CUtFMYmcMyVM/CCRmviAZgzf3Z+5u5hga7Z3jXsMZW82bkbcpqDxQeI/
E0ow8g49RYVW9QPC4TS5wdnwk2/gyxSF7SIC3nAAAAAwEAAQAAAQEAmqEVQ6akB9nD7TNB
jOFfXL+J5i+LSgKx6UTyIQGSNCW5V3NYhNabqKu2YCDfuRmjyPAnEDguSw50pKnPPMsclX
1asB0SOtGVCKTsWxFrZttiPtGSCbJm0qfXj6KXF8sC0cLPSbsSSVguHbbtqwQ76w8blTL7
jlk84pdQuESfeSrEFum5hIckC87zOh/FReNIQr4LS3mkT9ZBL3reN6q1EYZX2ANYwg7pl9
QO+xgcvuqNlZL9tzwitOiaTCXw8pfkI1Sa/P37hdAaygFqfoqkLP0ue8L19YUBNwgJoIOI
BvYx51+MlIYEHE/VAVx2yph207EdagnacXVWQlLvjnFtiQAAAIBUNuO7GfD/vHbB1FbNyG
czbpIHgWmF/IuxBYSpLUKTCNsvBfZZCqh3PG+DsGXbtbmuQySsL6ZC/LPCtJn5MvOQadRu
EycxshtPcZPdBWmwnRKTpgP5BqZ7oNWDZ5Uy5nGfgVzAAsLaAToqlSTQVIdIJJ38C17sP1
3nPiBsmKHCnwAAAIEA0x4Hd+usm82KsDmiLkrd22uk4RWtpagjCAh3k0YOkk/r3M4qCeZ2
iAuhc/dgixOPs0PZf6Ad3kIjJ8H/TNMG/GwmPLOpPKl1IPD/OFwcaQfamdH/teeYnVeH4c
EHWWLmHT8Wojey7hR/Ji1y9CrP+2TX6N2gcZTfUDRvSyBJY+0AAACBAM26gG0b+r3xnz6g
PHtsRGsORvAIcAhq91C+gOtYnbkpdqKuWEjuYXu20TBTVgTQ/6NoYDfxpskIxAwK1GjbjM
XpZ4c1GPfo8bvZsZ3i00I+qj/Dtp92KUQoPwi5sC6coRKNJrCSrgvxfbViVVrY9zi6aOmE
ZEkgoJu4I1SRhgajAAAAEnJzYUB0YXB3YXJkZW4tdGVzdA==
-----END OPENSSH PRIVATE KEY-----
";
