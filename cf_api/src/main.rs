use actix_web::{delete, get, post, put, App, HttpResponse, HttpServer, Responder};

use serde::{Deserialize, Serialize};

use std::net::Ipv4Addr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::cf_cli::CloudflareCli;

pub mod cf_cli;

#[derive(Serialize, Deserialize)]
pub enum CloudflareIngress {
    /// file doesn't exist yet
    DoesNotExist,
    /// the ingress file was found but it doesn't yet have the
    PartialIngress(String),
    /// ingress file exists and has all necessary information
    IngressReady(String),
}

#[get("/health")]
async fn health() -> impl Responder {
    info!("health check requested");
    HttpResponse::Ok().body("pong")
}

#[get("/list")]
async fn list_ingress_routes(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[post("/add")]
async fn add_route(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[delete("/remove")]
async fn remove_route(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

/// start a service which has already been configured
#[put("/start")]
async fn start(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

/// stop a configured service but do not remove it from registry
#[put("/stop")]
async fn stop(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    let cli = CloudflareCli::new();
    if cli.has_cert() {
        info!("Cloudflared certificate found");
    }
    static HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    static PORT: u16 = 8080;

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    HttpServer::new(|| App::new())
        .bind((HOST, PORT))
        .and_then(|r| {
            info!("Cloudflared Proxy API listening on {}:{}", HOST, PORT);
            Ok(r)
        })?
        .run()
        .await
}
