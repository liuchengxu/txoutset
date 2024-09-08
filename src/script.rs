use bitcoin::consensus::encode::Error;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::script::{Builder, ScriptBuf};
use bitcoin::{opcodes, PubkeyHash, PublicKey, ScriptHash};

const NUM_SPECIAL_SCRIPTS: usize = 6;
const MAX_SCRIPT_SIZE: usize = 10_000;

use crate::VarInt;

/// Wrapper to enable script decompression
#[derive(Debug, Eq, PartialEq)]
pub struct Script(ScriptBuf);

impl Script {
    pub fn from_bytes(script_buf: Vec<u8>) -> Self {
        Self(ScriptBuf::from_bytes(script_buf))
    }

    /// Reveal the inner script buffer
    pub fn into_inner(self) -> ScriptBuf {
        self.0
    }
}

impl From<ScriptBuf> for Script {
    fn from(script_buf: ScriptBuf) -> Self {
        Self(script_buf)
    }
}

impl Encodable for Script {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let script = self.0.as_script();
        let script_bytes = self.0.as_bytes();
        let size = script_bytes.len();

        if script.is_p2pkh() {
            // P2PKH
            VarInt::new(0x00).consensus_encode(writer)?;
            writer.write_all(&script_bytes[3..23])?; // 20 bytes pubkey hash
            Ok(21)
        } else if script.is_p2sh() {
            // P2SH
            VarInt::new(0x01).consensus_encode(writer)?;
            writer.write_all(&script_bytes[2..22])?; // 20 bytes script hash
            Ok(21)
        } else if let Some(pubkey) = script.p2pk_public_key() {
            if pubkey.compressed {
                // P2PK (compressed)
                VarInt::new(script_bytes[1] as u64).consensus_encode(writer)?;
                writer.write_all(&script_bytes[2..34])?; // 32 bytes pubkey
                Ok(33)
            } else {
                // P2PK (uncompressed)
                let compressed_pubkey = PublicKey::from_slice(&script_bytes[1..66])
                    .map_err(|err| {
                        bitcoin::io::Error::new(
                            bitcoin::io::ErrorKind::Other,
                            format!("Failed to deserialize public key: {err:?}"),
                        )
                    })?
                    .inner
                    .serialize();
                VarInt::new(compressed_pubkey[0] as u64 + 2).consensus_encode(writer)?;
                writer.write_all(&compressed_pubkey[1..33])?; // 32 bytes pubkey
                Ok(33)
            }
        } else if size > MAX_SCRIPT_SIZE {
            // OP_RETURN script
            writer.write_all(script_bytes)?;
            Ok(size)
        } else {
            // Custom script
            VarInt::new((size + NUM_SPECIAL_SCRIPTS) as u64).consensus_encode(writer)?;
            writer.write_all(script_bytes)?;
            Ok(size + 1)
        }
    }
}

impl Decodable for Script {
    fn consensus_decode<R: bitcoin::io::BufRead + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let mut size = u64::from(VarInt::consensus_decode(reader)?) as usize;

        match size {
            0x00 => {
                // P2PKH
                let mut bytes = [0; 20];
                reader.read_exact(&mut bytes)?;
                let pubkey_hash =
                    PubkeyHash::from_slice(&bytes).map_err(|_| Error::ParseFailed("HASH-160"))?;
                Ok(Script(ScriptBuf::new_p2pkh(&pubkey_hash)))
            }
            0x01 => {
                // P2SH
                let mut bytes = [0; 20];
                reader.read_exact(&mut bytes)?;
                let script_hash =
                    ScriptHash::from_slice(&bytes).map_err(|_| Error::ParseFailed("HASH-160"))?;
                Ok(Script(ScriptBuf::new_p2sh(&script_hash)))
            }
            0x02 | 0x03 => {
                // P2PK (compressed)
                let mut bytes = [0; 32];
                reader.read_exact(&mut bytes)?;

                let mut script_bytes = Vec::with_capacity(35);
                script_bytes.push(opcodes::all::OP_PUSHBYTES_33.to_u8());
                script_bytes.push(size as u8);
                script_bytes.extend_from_slice(&bytes);
                script_bytes.push(opcodes::all::OP_CHECKSIG.to_u8());

                Ok(Script(ScriptBuf::from(script_bytes)))
            }
            0x04 | 0x05 => {
                // P2PK (uncompressed)
                let mut bytes = [0; 32];
                reader.read_exact(&mut bytes)?;

                let mut compressed_pubkey_bytes = Vec::with_capacity(33);
                compressed_pubkey_bytes.push((size - 2) as u8);
                compressed_pubkey_bytes.extend_from_slice(&bytes);

                let compressed_pubkey = PublicKey::from_slice(&compressed_pubkey_bytes)
                    .map_err(|_| Error::ParseFailed("parse public key"))?;
                let inner_uncompressed = compressed_pubkey.inner.serialize_uncompressed();

                let mut script_bytes = Vec::with_capacity(67);
                script_bytes.push(opcodes::all::OP_PUSHBYTES_65.to_u8());
                script_bytes.extend_from_slice(&inner_uncompressed);
                script_bytes.push(opcodes::all::OP_CHECKSIG.to_u8());

                Ok(Script(ScriptBuf::from(script_bytes)))
            }
            _ => {
                size -= NUM_SPECIAL_SCRIPTS;
                let mut bytes = Vec::with_capacity(size);
                bytes.resize_with(size, || 0);
                if size > MAX_SCRIPT_SIZE {
                    reader.read_exact(&mut bytes)?;
                    let script = Builder::new()
                        .push_opcode(opcodes::all::OP_RETURN)
                        .into_script();
                    Ok(Script(script))
                } else {
                    reader.read_exact(&mut bytes)?;
                    Ok(Script(ScriptBuf::from_bytes(bytes)))
                }
            }
        }
    }
}
