use tokio;
use pgwire::pg_server::{PgServer, PgConfig, ServerParameterProvider};
use std::net::SocketAddr;
use log::{info, error};
use env_logger;
use async_trait::async_trait;
use pgwire::pg_server::{PgWireConnectionState, PgWireUserAuthenticator, UserAuthCredential, BoxedError};
use pgwire::api::auth::Password;
use pgwire::api::query::{SimpleQueryHandler, SimpleQueryResponse};
use tokio_postgres::{NoTls, Client};

// Struct for handling requests and authentication
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

        // Replace this block with actual authentication logic (e.g., check against your system)
        if username == "valid_user" && password == "valid_password" {
            info!("Authentication successful for user: {}", username);
            Ok(())
        } else {
            error!("Authentication failed for user: {}", username);
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
        // Example of connecting to an actual PostgreSQL database
        let (client, connection) = tokio_postgres::connect(
            "host=localhost user=postgres password=your_db_password", NoTls,
        ).await.map_err(|e| {
            error!("Failed to connect to database: {}", e);
            "Database connection error"
        })?;

        // Spawn the connection object to process notifications
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("Connection error: {}", e);
            }
        });

        // Example: Execute a basic query
        let rows = client.simple_query(query).await.map_err(|e| {
            error!("Failed to execute query: {}", e);
            "Query execution error"
        })?;

        let response = SimpleQueryResponse::new(rows);
        Ok(response)
    }
}

#[async_trait]
impl ServerParameterProvider for TwentyPgHandler {
    async fn server_parameters(&self) -> Result<Vec<(String, String)>, BoxedError> {
        Ok(vec![("application_name".to_string(), "TwentyPostgresProxy".to_string())])
    }
}

// Whitelisting IP addresses
fn is_ip_allowed(ip: std::net::IpAddr) -> bool {
    // Customize this to implement IP whitelisting logic
    // Example: Only allow localhost for now
    if ip == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)) {
        true
    } else {
        error!("IP address {} is not allowed", ip);
        false
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let addr = "0.0.0.0:5433".parse::<SocketAddr>().unwrap();
    let config = PgConfig::new().with_addr(addr);

    let authenticator = TwentyPgHandler;
    let handler = TwentyPgHandler;

    let server = PgServer::new(config, authenticator, handler);

    info!("Starting twenty-postgres-proxy on {}", addr);

    // Wrap the server with IP filtering
    if let Err(e) = server
        .with_middleware(|client_addr, _| {
            if is_ip_allowed(client_addr.ip()) {
                Ok(())
            } else {
                Err("IP not allowed".into())
            }
        })
        .serve()
        .await
    {
        error!("Server error: {:?}", e);
    }
}
