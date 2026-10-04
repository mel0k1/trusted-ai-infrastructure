//! RFC-3161: минимальный клиент TSA — TimeStampReq в DER, разбор TimeStampResp,
//! сохранение .tsr и офлайн-проверка отпечатков по логу.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::{Anchor, AuditError, ChainedEvent, Checkpoint};

#[derive(Debug, Error)]
pub enum TsaError {
    #[error("http: {0}")]
    Http(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("der: {0}")]
    Der(&'static str),
    #[error("tsa status {0}")]
    Status(u64),
    #[error("imprint mismatch")]
    Imprint,
}

/// Разобранный TSTInfo: серийник, время TSA и отпечаток из токена.
#[derive(Debug, Clone)]
pub struct TstInfo {
    pub serial: Vec<u8>,
    pub gen_time: String,
    pub imprint: Vec<u8>,
}

const SHA256: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 1];

// --- минимальный DER ---

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}

/// (tag, content, сколько байт занял элемент)
fn parse_tlv(data: &[u8]) -> Result<(u8, &[u8], usize), TsaError> {
    if data.len() < 2 {
        return Err(TsaError::Der("short"));
    }
    let tag = data[0];
    let lb = data[1];
    let (hlen, clen) = if lb < 0x80 {
        (2usize, lb as usize)
    } else {
        let n = (lb & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(TsaError::Der("len"));
        }
        let mut l = 0usize;
        for &b in &data[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (2 + n, l)
    };
    if data.len() < hlen + clen {
        return Err(TsaError::Der("truncated"));
    }
    Ok((tag, &data[hlen..hlen + clen], hlen + clen))
}

/// Дети SEQUENCE/SET.
fn children(seq: &[u8]) -> Result<Vec<(u8, &[u8])>, TsaError> {
    let mut out = Vec::new();
    let mut rest = seq;
    while !rest.is_empty() {
        let (tag, body, used) = parse_tlv(rest)?;
        out.push((tag, body));
        rest = &rest[used..];
    }
    Ok(out)
}

fn b128(out: &mut Vec<u8>, v: u64) {
    let mut tmp = vec![v as u8 & 0x7f];
    let mut v = v >> 7;
    while v > 0 {
        tmp.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    tmp.reverse();
    out.extend_from_slice(&tmp);
}

fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    b128(&mut out, arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        b128(&mut out, *a);
    }
    out
}

fn be_min(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(7);
    let mut out = be[first..].to_vec();
    if out.is_empty() || out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    out
}

fn int_value(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    v
}

// --- TimeStampReq / TimeStampResp ---

/// TimeStampReq: sha256-отпечаток + nonce, без certReq (default false).
pub fn time_stamp_req(imprint: &[u8], nonce: u64) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, &oid(&SHA256)), tlv(0x05, &[])].concat());
    let imprint_seq = tlv(0x30, &[alg, tlv(0x04, imprint)].concat());
    let version = tlv(0x02, &[1]);
    let nonce_der = tlv(0x02, &be_min(nonce));
    tlv(0x30, &[version, imprint_seq, nonce_der].concat())
}

fn parse_resp(resp: &[u8]) -> Result<Option<TstInfo>, TsaError> {
    let (tag, top, _) = parse_tlv(resp)?;
    if tag != 0x30 {
        return Err(TsaError::Der("resp not seq"));
    }
    let kids = children(top)?;
    if kids.is_empty() {
        return Err(TsaError::Der("empty resp"));
    }
    let status = children(kids[0].1)?;
    if status.is_empty() || status[0].0 != 0x02 {
        return Err(TsaError::Der("status"));
    }
    let code = int_value(status[0].1);
    // 0 granted, 1 grantedWithMods; остальное — отказ
    if code > 1 {
        return Err(TsaError::Status(code));
    }
    match kids.get(1) {
        None => Ok(None),
        Some((0x30, token)) => parse_token(token).map(Some),
        Some(_) => Err(TsaError::Der("token")),
    }
}

fn parse_token(content: &[u8]) -> Result<TstInfo, TsaError> {
    // ContentInfo: SEQ { OID, [0] EXPLICIT SignedData }, здесь — её содержимое
    let ci = children(content)?;
    if ci.len() < 2 || ci[1].0 != 0xA0 {
        return Err(TsaError::Der("no signeddata"));
    }
    let (_, sd, _) = parse_tlv(ci[1].1)?;
    // SignedData: INT, SET, SEQ(encap), [0] certs?, SET(signerInfos)
    let sd_kids = children(sd)?;
    if sd_kids.len() < 3 || sd_kids[2].0 != 0x30 {
        return Err(TsaError::Der("no encap"));
    }
    let encap = children(sd_kids[2].1)?;
    if encap.len() < 2 || encap[1].0 != 0xA0 {
        return Err(TsaError::Der("no tstinfo"));
    }
    // [0] EXPLICIT → OCTET STRING → TSTInfo TLV → её содержимое
    let (_, tst_der, _) = parse_tlv(encap[1].1)?;
    let (_, tst_body, _) = parse_tlv(tst_der)?;
    let tst = children(tst_body)?;
    if tst.len() < 5 || tst[2].0 != 0x30 {
        return Err(TsaError::Der("tstinfo"));
    }
    let mi = children(tst[2].1)?;
    if mi.len() < 2 {
        return Err(TsaError::Der("imprint"));
    }
    Ok(TstInfo {
        imprint: mi[1].1.to_vec(),
        serial: tst[3].1.to_vec(),
        gen_time: String::from_utf8_lossy(tst[4].1).into_owned(),
    })
}

/// Разбирает .tsr и сверяет отпечаток с ожидаемым sha256-дайджестом.
pub fn verify_tsr(tsr: &[u8], digest: [u8; 32]) -> Result<TstInfo, TsaError> {
    let info = parse_resp(tsr)?.ok_or(TsaError::Der("no token"))?;
    if info.imprint != digest {
        return Err(TsaError::Imprint);
    }
    Ok(info)
}

// --- якорь ---

/// TSA-якорь: голова лога штампуется на RFC-3161 сервисе,
/// сырой ответ сохраняется в {dir}/{height}.tsr для офлайн-проверки.
pub struct Rfc3161Anchor {
    url: String,
    dir: PathBuf,
    http: ureq::Agent,
}

impl Rfc3161Anchor {
    pub fn new(url: impl Into<String>, dir: impl Into<PathBuf>) -> Self {
        Self {
            url: url.into(),
            dir: dir.into(),
            http: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build(),
        }
    }

    /// Штампует готовый sha256-дайджест, сохраняет ответ, возвращает TSTInfo.
    pub fn stamp(&self, name: &str, digest: &[u8; 32]) -> Result<TstInfo, TsaError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let req = time_stamp_req(digest, nonce);
        let resp = self.send(&req)?;
        let info = parse_resp(&resp)?.ok_or(TsaError::Der("no token"))?;
        if info.imprint != *digest {
            return Err(TsaError::Imprint);
        }
        std::fs::create_dir_all(&self.dir)?;
        std::fs::write(self.dir.join(format!("{name}.tsr")), &resp)?;
        Ok(info)
    }

    fn send(&self, req: &[u8]) -> Result<Vec<u8>, TsaError> {
        let resp = self
            .http
            .post(&self.url)
            .set("Content-Type", "application/timestamp-query")
            .set("Accept", "application/timestamp-reply")
            .send_bytes(req)
            .map_err(|e| match e {
                ureq::Error::Status(code, r) => TsaError::Http(format!(
                    "status {code}: {}",
                    r.into_string().unwrap_or_default()
                )),
                ureq::Error::Transport(t) => TsaError::Http(t.to_string()),
            })?;
        let mut body = Vec::new();
        resp.into_reader().read_to_end(&mut body)?;
        Ok(body)
    }
}

impl Anchor for Rfc3161Anchor {
    fn anchor(&self, cp: &Checkpoint) -> Result<(), AuditError> {
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&cp.head, &mut digest)
            .map_err(|_| AuditError::Anchor("head not hex32".into()))?;
        self.stamp(&cp.height.to_string(), &digest)
            .map_err(|e| AuditError::Anchor(e.to_string()))?;
        Ok(())
    }
}

/// Сверяет .tsr-каталог с логом: verify цепочки + отпечаток каждого токена
/// совпадает с головой лога на его высоте. Возвращает число проверенных токенов.
pub fn verify_tsr_dir(
    log_path: impl AsRef<Path>,
    dir: impl AsRef<Path>,
) -> Result<usize, AuditError> {
    crate::verify(log_path.as_ref())?;

    let content = std::fs::read_to_string(log_path.as_ref())?;
    let mut heads = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let c: ChainedEvent = serde_json::from_str(line).map_err(|source| AuditError::Json {
            line: i + 1,
            source,
        })?;
        heads.push(c.hash);
    }

    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir.as_ref())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.to_str() == Some("tsr"))
        })
        .map(|e| e.path())
        .collect();
    entries.sort();

    let count = entries.len();
    for path in &entries {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let height: usize = name
            .trim_end_matches(".tsr")
            .parse()
            .map_err(|_| AuditError::Anchor(format!("bad tsr name: {name}")))?;
        if height == 0 || height > heads.len() {
            return Err(AuditError::Anchor(format!(
                "tsr height {height} out of range"
            )));
        }
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&heads[height - 1], &mut digest)
            .map_err(|_| AuditError::Anchor("head not hex32".into()))?;
        let tsr = std::fs::read(path)?;
        verify_tsr(&tsr, digest).map_err(|e| AuditError::Anchor(e.to_string()))?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditLog, Event};
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    // фикстура: полный TimeStampResp с токеном вокруг заданного отпечатка
    fn token_der(imprint: &[u8], gen_time: &str, serial: u64) -> Vec<u8> {
        let alg = tlv(0x30, &[tlv(0x06, &oid(&SHA256)), tlv(0x05, &[])].concat());
        let mi = tlv(0x30, &[alg, tlv(0x04, imprint)].concat());
        let tst = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x06, &oid(&[1, 2, 3, 4])),
                mi,
                tlv(0x02, &be_min(serial)),
                tlv(0x18, gen_time.as_bytes()),
            ]
            .concat(),
        );
        let encap = tlv(
            0x30,
            &[
                tlv(0x06, &oid(&[1, 2, 840, 113549, 1, 9, 16, 1, 4])),
                tlv(0xA0, &tlv(0x04, &tst)),
            ]
            .concat(),
        );
        let sd = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x31, &[]),
                encap,
                tlv(0xA0, &[]),
                tlv(0x31, &[]),
            ]
            .concat(),
        );
        tlv(
            0x30,
            &[
                tlv(0x06, &oid(&[1, 2, 840, 113549, 1, 7, 2])),
                tlv(0xA0, &sd),
            ]
            .concat(),
        )
    }

    fn status_seq(code: u8) -> Vec<u8> {
        tlv(0x30, &[tlv(0x02, &[code])].concat())
    }

    fn granted_resp(imprint: &[u8], gen_time: &str, serial: u64) -> Vec<u8> {
        let status = status_seq(0);
        let token = token_der(imprint, gen_time, serial);
        tlv(0x30, &[status, token].concat())
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tai-tsa-{}-{tag}", std::process::id()))
    }

    #[test]
    fn req_contains_imprint_and_nonce() {
        let req = time_stamp_req(&[0xAA; 32], 7);
        let (_, top, _) = parse_tlv(&req).unwrap();
        let kids = children(top).unwrap();
        assert_eq!(kids.len(), 3);
        assert_eq!(kids[0].0, 0x02);
        assert_eq!(kids[0].1, &[1]);
        assert_eq!(kids[1].0, 0x30);
        let mi = children(kids[1].1).unwrap();
        assert_eq!(mi[1].0, 0x04);
        assert_eq!(mi[1].1, &[0xAA; 32]);
        assert_eq!(int_value(kids[2].1), 7);
    }

    #[test]
    fn resp_without_token_is_none() {
        let resp = tlv(0x30, &[status_seq(0)].concat());
        assert!(parse_resp(&resp).unwrap().is_none());
    }

    #[test]
    fn rejected_status_is_error() {
        let resp = tlv(0x30, &[status_seq(2)].concat());
        assert!(matches!(parse_resp(&resp), Err(TsaError::Status(2))));
    }

    #[test]
    fn token_roundtrip_and_verify() {
        let resp = granted_resp(&[0x42; 32], "20261004120000Z", 9);
        let info = verify_tsr(&resp, [0x42; 32]).unwrap();
        assert_eq!(info.gen_time, "20261004120000Z");
        assert_eq!(int_value(&info.serial), 9);
        assert!(matches!(
            verify_tsr(&resp, [0x43; 32]),
            Err(TsaError::Imprint)
        ));
    }

    // локальный mock-TSA: отвечает granted с отпечатком из запроса
    fn mock_tsa() -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for i in 0..2 {
                let (mut sock, _) = listener.accept().unwrap();
                // читаем до конца тела по Content-Length
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = sock.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let cl: usize = headers
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + cl {
                        break;
                    }
                }
                let req = &buf;
                let pos = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let (_, top, _) = parse_tlv(&req[pos..]).unwrap();
                let kids = children(top).unwrap();
                let mi = children(kids[1].1).unwrap();
                let resp = granted_resp(mi[1].1, "20261004120000Z", i as u64 + 1);
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp.len()
                );
                sock.write_all(http.as_bytes()).unwrap();
                sock.write_all(&resp).unwrap();
            }
        });
        (format!("http://{addr}/tsr"), handle)
    }

    #[test]
    fn anchor_roundtrip_via_mock_tsa() {
        let dir = temp_dir("anchor");
        let log = dir.join("log.jsonl");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (url, server) = mock_tsa();
        {
            let anchor = Rfc3161Anchor::new(&url, &dir);
            let alog = AuditLog::file_anchored(&log, Box::new(anchor), 2).unwrap();
            for i in 0..4 {
                alog.log(&Event::now("k", "x", i.to_string()));
            }
        }
        server.join().unwrap();
        assert_eq!(verify_tsr_dir(&log, &dir).unwrap(), 2);

        // подменённый токен ломает проверку
        std::fs::write(
            dir.join("2.tsr"),
            granted_resp(&[0x00; 32], "20261004120000Z", 2),
        )
        .unwrap();
        assert!(verify_tsr_dir(&log, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    #[ignore] // живая сеть
    fn live_freetsa_grants_token() {
        let dir = std::env::temp_dir().join("tai-freetsa-live");
        let anchor = Rfc3161Anchor::new("http://freetsa.org/tsr", &dir);
        let digest: [u8; 32] = Sha256::digest(b"tai-live-test").into();
        let info = anchor.stamp("live", &digest).unwrap();
        assert_eq!(info.imprint, digest);
    }
}
