use md5;
use std::net::Ipv4Addr;
pub trait Serialize {
    fn encode(&self) -> Vec<u8>;
}
pub trait Deserialize: Sized {
    fn decode(slice: &[u8]) -> anyhow::Result<Self>;
}
pub trait Message {}
pub mod login {
    use super::*;
    use anyhow::bail;

    #[derive(Debug)]
    pub struct LoginRequest<'a> {
        user: &'a str,
        pass: &'a str,
    }
    impl Message for LoginRequest<'_> {}
    impl Serialize for LoginRequest<'_> {
        fn encode(&self) -> Vec<u8> {
            let user = self.user;
            let pass = self.pass;
            let user_len = user.len() as u32;
            let pass_len = pass.len() as u32;

            let message_length = 4 + 4 + user_len + 4 + pass_len + 4 + 4 + 32 + 4;
            let message_code = 1u32;

            let version = 160u32;
            let minor_version = 1u32;

            let hash = {
                let mut buff = user.as_bytes().to_vec();
                buff.extend(pass.as_bytes());
                let digest = md5::compute(&buff);
                format!("{:x}", digest)
            };
            let mut buffer = Vec::new();
            buffer.extend(&message_length.to_le_bytes());
            buffer.extend(&message_code.to_le_bytes());
            buffer.extend(&user_len.to_le_bytes());
            buffer.extend(user.as_bytes());
            buffer.extend(&pass_len.to_le_bytes());
            buffer.extend(pass.as_bytes());
            buffer.extend(&version.to_le_bytes());
            buffer.extend(&(32u32).to_le_bytes());
            buffer.extend(hash.as_bytes());
            buffer.extend(&minor_version.to_le_bytes());

            buffer
        }
    }
    impl<'a> LoginRequest<'a> {
        pub fn new(user: &'a str, pass: &'a str) -> Self {
            Self { user, pass }
        }
    }

    #[derive(Debug)]
    pub enum LoginResponse {
        Success {
            ip: Ipv4Addr,
            hash: Vec<u8>,
            supporter: bool,
        },
        Fail {
            reason: String,
        },
    }
    impl Message for LoginResponse {}
    impl Deserialize for LoginResponse {
        fn decode(slice: &[u8]) -> anyhow::Result<Self> {
            let success = slice.get(0) == Some(&1);

            if success {
                let supporter = slice
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("Inappropriate length: {}", slice.len()))?;
                let supporter = match *supporter {
                    0 | 1 => *supporter == 1,
                    _ => bail!("Invalid supporter byte"),
                };

                let slice = &slice[..slice.len() - 1];
                if slice.len() < 37 {
                    bail!("Slice is too short to contain hash and IP address");
                }

                let hash = slice[slice.len() - 32..].to_vec();

                let ip_bits = slice
                    .get(slice.len() - 36..slice.len() - 32)
                    .ok_or_else(|| anyhow::anyhow!("Invalid slice length for IP address"))?;
                let ip = Ipv4Addr::new(ip_bits[0], ip_bits[1], ip_bits[2], ip_bits[3]);

                Ok(Self::Success {
                    ip,
                    hash,
                    supporter,
                })
            } else {
                let reason = String::from_utf8_lossy(&slice[1..]).to_string();
                Ok(Self::Fail { reason })
            }
        }
    }
}

pub mod message {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::{Deserialize, Message, Serialize};
    use anyhow::bail;

    #[derive(Debug)]
    pub struct Msg<T>
    where
        T: Message,
    {
        tag: MessageTag,
        message: T,
    }
    #[derive(Debug)]
    pub enum MessageTag {
        Login = 1,
    }
    impl MessageTag {
        pub fn from(i: u32) -> anyhow::Result<Self> {
            match i {
                1 => Ok(Self::Login),
                _ => bail!("Not Found"),
            }
        }
    }
    impl<T> Msg<T>
    where
        T: Message,
    {
        pub async fn recv<S>(stream: &mut S) -> anyhow::Result<Self>
        where
            S: AsyncRead + Unpin,
            T: Deserialize,
        {
            let length = stream.read_u32_le().await? - 4;
            let tag = {
                let value = stream.read_u32_le().await?;
                MessageTag::from(value)?
            };
            let mut buffer = vec![0u8; length as usize];
            stream.read_exact(&mut buffer).await?;
            let message = T::decode(&buffer)?;
            Ok(Self { tag, message })
        }
        pub async fn send<S>(t: T, stream: &mut S) -> anyhow::Result<()>
        where
            S: AsyncWrite + Unpin,
            T: Serialize,
        {
            let payload = t.encode();
            stream.write_all(&payload).await?;
            Ok(())
        }
    }
}
