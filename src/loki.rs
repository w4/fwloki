#[allow(clippy::default_trait_access)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/logproto.rs"));
}

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use prost::Message;
use snap::raw::{max_compress_len, Encoder as SnappyEncoder};

pub fn create_push_request(
    snappy: &mut SnappyEncoder,
    encode_buf: &mut BytesMut,
    compress_buf: &mut BytesMut,
    entries: &mut Vec<(i64, String)>,
) -> Result<Bytes> {
    let entries = entries
        .drain(..)
        .map(|(timestamp, line)| proto::EntryAdapter {
            timestamp: Some(prost_types::Timestamp {
                seconds: timestamp,
                nanos: 0,
            }),
            line,
        })
        .collect();

    let req = proto::PushRequest {
        streams: vec![proto::StreamAdapter {
            labels: "{namespace=\"iptables\"}".to_string(),
            entries,
        }],
    };

    // encode the PushRequest
    let encoded_len = req.encoded_len();
    if encode_buf.capacity() < encoded_len {
        encode_buf.reserve(encoded_len);
    }

    req.encode(encode_buf)?;
    let encoded_bytes = encode_buf.split().freeze();

    // compress the PushRequest
    let max_compress_len = max_compress_len(encoded_len);
    if compress_buf.len() < max_compress_len {
        // we resize the buffer instead of reserving capacity because we need
        // the array to be initialized so when we pass the backing `&mut [u8]`
        // the whole capacity is ready to be written into
        compress_buf.resize(max_compress_len, 0);
    }

    let len = snappy.compress(&encoded_bytes, &mut compress_buf[..])?;
    let compressed_bytes = compress_buf.split_to(len).freeze();

    Ok(compressed_bytes)
}
