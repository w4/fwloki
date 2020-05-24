#[allow(clippy::default_trait_access)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/logproto.rs"));
}

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use prost::Message;

pub fn create_push_request(entries: Vec<(i64, String)>) -> Result<Bytes> {
    let mut entries_transformed = Vec::new();
    for (timestamp, line) in entries {
        entries_transformed.push(proto::EntryAdapter {
            timestamp: Some(prost_types::Timestamp {
                seconds: timestamp,
                nanos: 0,
            }),
            line,
        });
    }

    let req = proto::PushRequest {
        streams: vec![proto::StreamAdapter {
            labels: "{namespace=\"iptables\"}".to_string(),
            entries: entries_transformed,
        }],
    };

    let mut s = BytesMut::new();
    req.encode(&mut s)?;
    let s = s.freeze();

    // TODO: can we do this without the copy?
    Ok(Bytes::from(
        snap::raw::Encoder::new().compress_vec(s.as_ref())?,
    ))
}
