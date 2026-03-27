use futures_util::Stream;
use hyper::body::Bytes;
use reqwest::Client;
use tokio::sync::mpsc;
use tracing::debug;

use crate::config::Upstream;

/// Events emitted by the upstream proxy.
pub enum ProxyEvent {
    /// A chunk of data (SSE line or full response body).
    Chunk(String),
    /// Stream complete.
    Done,
    /// Error occurred.
    Error(String),
}

/// Proxy a request to the upstream backend (HTTP or Unix socket).
pub async fn proxy_to_upstream(
    upstream: &Upstream,
    client: &Client,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    is_stream: bool,
    tx: mpsc::Sender<ProxyEvent>,
) {
    match upstream {
        Upstream::Http { url } => {
            proxy_http(client, url, method, path, body, is_stream, tx).await;
        }
        Upstream::Unix { path: sock_path } => {
            proxy_unix(sock_path, method, path, body, is_stream, tx).await;
        }
    }
}

/// Proxy via HTTP (reqwest).
async fn proxy_http(
    client: &Client,
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    is_stream: bool,
    tx: mpsc::Sender<ProxyEvent>,
) {
    let url = format!("{base_url}{path}");
    debug!(url = %url, method, stream = is_stream, "proxying to upstream (http)");

    let req = match method.to_uppercase().as_str() {
        "POST" => {
            let mut r = client.post(&url);
            if let Some(b) = body {
                r = r.json(b);
            }
            r
        }
        _ => client.get(&url),
    };

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let _ = tx
            .send(ProxyEvent::Error(format!("upstream {status}: {body}")))
            .await;
        return;
    }

    if is_stream {
        stream_sse(resp.bytes_stream(), tx).await;
    } else {
        match resp.text().await {
            Ok(text) => {
                let _ = tx.send(ProxyEvent::Chunk(text)).await;
                let _ = tx.send(ProxyEvent::Done).await;
            }
            Err(e) => {
                let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
            }
        }
    }
}

/// Proxy via Unix domain socket (hyper).
async fn proxy_unix(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    is_stream: bool,
    tx: mpsc::Sender<ProxyEvent>,
) {
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;

    debug!(
        socket = socket_path,
        path,
        method,
        stream = is_stream,
        "proxying to upstream (unix)"
    );

    let stream = match tokio::net::UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx
                .send(ProxyEvent::Error(format!("unix connect: {e}")))
                .await;
            return;
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            let _ = tx
                .send(ProxyEvent::Error(format!("unix handshake: {e}")))
                .await;
            return;
        }
    };
    tokio::spawn(conn);

    let req_body = body
        .map(|b| serde_json::to_vec(b).unwrap_or_default())
        .unwrap_or_default();

    let hyper_method = match method.to_uppercase().as_str() {
        "POST" => hyper::Method::POST,
        "PUT" => hyper::Method::PUT,
        "DELETE" => hyper::Method::DELETE,
        _ => hyper::Method::GET,
    };

    let req = match hyper::Request::builder()
        .method(hyper_method)
        .uri(path)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(req_body)))
    {
        Ok(r) => r,
        Err(e) => {
            let _ = tx
                .send(ProxyEvent::Error(format!("build request: {e}")))
                .await;
            return;
        }
    };

    let resp = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
            return;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map(|c| String::from_utf8_lossy(&c.to_bytes()).into_owned())
            .unwrap_or_default();
        let _ = tx
            .send(ProxyEvent::Error(format!("upstream {status}: {body}")))
            .await;
        return;
    }

    if is_stream {
        // Convert hyper body frames into a bytes stream for the generic SSE parser
        use futures_util::StreamExt;
        use http_body_util::BodyStream;
        let body_stream = Box::pin(BodyStream::new(resp.into_body()).filter_map(|frame| async {
            match frame {
                Ok(f) => f.into_data().ok().map(Ok),
                Err(e) => Some(Err(e)),
            }
        }));
        stream_sse(body_stream, tx).await;
    } else {
        match resp.into_body().collect().await {
            Ok(collected) => {
                let text = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
                let _ = tx.send(ProxyEvent::Chunk(text)).await;
                let _ = tx.send(ProxyEvent::Done).await;
            }
            Err(e) => {
                let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
            }
        }
    }
}

/// Parse SSE stream from any bytes stream.
async fn stream_sse<S, E>(stream: S, tx: mpsc::Sender<ProxyEvent>)
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    use futures_util::StreamExt;

    let mut stream = stream;
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => {
                let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
                return;
            }
        };

        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(e) => {
                let _ = tx.send(ProxyEvent::Error(e.to_string())).await;
                return;
            }
        };

        buffer.push_str(text);

        // Process complete lines
        while let Some(pos) = buffer.find('\n') {
            let line = buffer[..pos].to_string();
            buffer = buffer[pos + 1..].to_string();

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    let _ = tx.send(ProxyEvent::Done).await;
                    return;
                }
                let _ = tx.send(ProxyEvent::Chunk(data.to_string())).await;
            }
        }
    }

    // Stream ended without [DONE] sentinel — still signal done
    let _ = tx.send(ProxyEvent::Done).await;
}
