use messages::{login::{LoginRequest, LoginResponse}, message::{self, Msg}, Message};
use tokio::net::TcpStream;

pub mod messages;

#[tokio::test]
async fn login_message() -> anyhow::Result<()> {
    let login = LoginRequest::new("random", "random123");
    let mut stream = TcpStream::connect("0.0.0.0:2242").await?;
    if Msg::send(login, &mut stream).await.is_ok(){
        let message: Msg<LoginResponse> = Msg::recv(&mut stream).await?;
        dbg!(&message);
    }
    Ok(())
}
