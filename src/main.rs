use tokio;
use pgwire::pg_server::{PgServer, PgConfig};
use std::net::SocketAddr;
use log::{info, error};
use env_logger;
use async_trait::async_trait;
use pgwire::pg_server::{PgWireConnectionState, PgWireUserAuthenticator, UserAuthCredential, BoxedError};
use pgwire::api::auth::Password;
use pgwire::api::query::{SimpleQueryHandler, SimpleQueryResponse};

struct TwentyPgHandler;

#[async_trait]
impl PgWireUserAuthenticator for TwentyPgHandler {
    async fn authenticate(
        &self,
        credentials: &UserAuthCredential,
    ) -> Result<(), BoxedError> {
        let username = &credentials.user;
        let password = match &credentials.password {
            Some(Password::Plain(p)) => p,
            _ => "",
        };

        // TODO: Verify if the user has opted-in and credentials are valid
        // For now, allow all connections
        if username == "valid_user" && password == "valid_password" {
            Ok(())
        } else {
            Err("Authentication failed".into())
        }
    }
}

#[async_trait]
impl SimpleQueryHandler for TwentyPgHandler {
    async fn do_query(
        &self,
        query: &str,
        _pg_session: &mut PgWireConnectionState,
    ) -> Result<SimpleQueryResponse, BoxedError> {
        // TODO: Forward the query to the PostgreSQL database
        Err("Not implemented".into())
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = "127.0.0.1:5433".parse::<SocketAddr>().unwrap();
    let config = PgConfig::new().with_addr(addr);

    let server = PgServer::new(config, TwentyPgHandler, TwentyPgHandler);

    info!("Starting twenty-postgres-proxy on {}", addr);

    if let Err(e) = server.serve().await {
        error!("Server error: {:?}", e);
    }
}
