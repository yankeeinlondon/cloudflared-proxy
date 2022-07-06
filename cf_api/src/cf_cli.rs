use chrono::{DateTime, Utc};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, fs, path::Path, process::Command};
use tracing::{debug, error, instrument, warn};

impl CloudflareCert {
    pub fn get() -> Self {
        let cert = fs::read_to_string("/etc/hosts");
        match cert {
            Ok(cert) => CloudflareCert::Cert(cert),
            Err(_) => CloudflareCert::DoesNotExist,
        }
    }

    pub fn ready(&self) -> bool {
        match &self {
            Self::DoesNotExist => false,
            Self::Cert(_) => true,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProxyDashboard {
    id: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum TunnelStatus {
    Up(Vec<Tunnel>),
    ParseError(String),
    NoCert(String),
}

#[derive(Serialize, Deserialize)]
pub enum CloudflareCert {
    /// file doesn't exist yet
    DoesNotExist,
    /// certificate file info
    Cert(String),
}

#[derive(Serialize, Deserialize)]
pub struct IngressConfig {
    credentials: CloudflareCredentials,
    ingress: IngressRule,
}

#[derive(Serialize, Deserialize)]
#[serde(rename = "PascalCase")]
pub struct CloudflareCredentials {
    account_tag: String,
    tunnel_secret: String,
    tunnel_ID: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IngressRule {
    /// The external DNS entry which cloudflare is managing
    hostname: String,
    /// Optionally, a regular expression can be used to test the URL path
    path: Option<String>,
    /// The service is the local/private service which is being exposed.
    ///
    /// Examples:
    /// - https://localhost:8003
    /// - http_status:404
    #[serde(default = "default_service")]
    service: String,
}

fn default_service() -> String {
    String::from("http_status:404")
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IngressFallback {
    /// The service which will be used if no prior Ingress routes are
    /// a match. Defaults to 404 response.
    ///
    /// @default http_status:404
    #[serde(default = "default_service")]
    service: String,
}

impl IngressFallback {
    pub fn new(service: &str) -> IngressFallback {
        IngressFallback {
            service: service.to_string(),
        }
    }
    pub fn default() -> IngressFallback {
        IngressFallback {
            service: default_service(),
        }
    }
}

/// A `Tunnel` can contain 0:M _connections_
#[derive(Serialize, Deserialize, Clone)]
pub struct Connection {
    colo_name: String,
    id: String,
    is_pending_reconnection: bool,
    origin_ip: String,
    opened_at: DateTime<Utc>,
}

/// Cloudflared Tunnel Definition
#[derive(Serialize, Deserialize, Clone)]
pub struct Tunnel {
    id: String,
    /// name of the tunnel, which will create a CNAME off of
    /// the base domain this tunnel is working off of.
    name: String,
    created_at: DateTime<Utc>,
    deleted_at: DateTime<Utc>,
    /// a list of connections provided over this tunnel
    connections: Vec<Connection>,
}

impl Tunnel {
    pub fn list() -> Vec<Tunnel> {
        let json = Command::new("cloudflared") //
            .args(["tunnel", "list", "-o", "json"])
            .output();
        match json {
            Ok(json) => {
                return vec![];
            }
            Err(err) => {
                warn!("Error trying to get list of tunnels: {}", err);

                return vec![];
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum IngressFileRule {
    /// an ingress route
    Rule(IngressRule),
    /// the fallback route, with is a normal route rule but without a hostname
    Fallback(IngressFallback),
}

/// An ingress file leads with credentials and then supplies
/// routes with an optional "fallback" at the end.
#[derive(Serialize, Deserialize)]
struct IngressFile {
    tunnel: String,
    credentials_file: String,
    ingress: Vec<IngressFileRule>,
}

/// get's an ingress file from the filesystem and passes
/// back as struct. Receives a "filename" which does
/// not include the file extension so that we may try
/// both ".yaml" and ".yml".
fn get_ingress_file(filename: &str) -> Option<IngressFile> {
    let yml = filename.clone().to_string();
    yml.push_str(".yml");
    let yml = Path::new(&yml);
    let yaml = filename.clone().to_string();
    yaml.push_str(".yaml");
    let yaml = Path::new(&yaml);

    match (yml.exists(), yaml.exists()) {
        (true, false) => {
            let data = fs::read_to_string(yml).unwrap();
            let ingress: IngressFile = serde_yaml::from_str(&data).unwrap();
            Some(ingress)
        }
        (false, true) => {
            let data = fs::read_to_string(yaml).unwrap();
            let ingress: IngressFile = serde_yaml::from_str(&data).unwrap();
            Some(ingress)
        }
        (true, true) => {
            warn!(
                "The shared volume has a .yml and .yaml for the same tunnel, in this case the .yml file will be used: {}",
                yml.to_string_lossy()
            );
            let data = fs::read_to_string(yml).unwrap();
            let ingress: IngressFile = serde_yaml::from_str(&data).unwrap();
            Some(ingress)
        }
        (false, false) => None,
    }
}

#[derive(Serialize, Deserialize)]
struct ManagedTunnel {
    file_name: String,
    account_tag: String,
    tunnel_secret: String,
    tunnel_id: String,
    ingress_rules: Vec<IngressRule>,
    ingress_fallback: IngressFallback,
}

impl ManagedTunnel {
    pub fn new(file_name: &str, credentials: &CloudflareCredentials) -> ManagedTunnel {
        ManagedTunnel {
            file_name: String::from(file_name),
            account_tag: credentials.account_tag,
            tunnel_secret: credentials.tunnel_secret,
            tunnel_id: credentials.tunnel_ID,
            ingress_rules: vec![],
            ingress_fallback: IngressFallback::default(),
        }
    }

    pub fn has_ingress(&self) -> bool {
        &self.ingress_rules.len() > &0
    }

    /// builds the full list of managed tunnels by
    /// finding all `.json` files in the shared volume
    /// mount directory and then afterward looking
    /// for Ingress in `.yaml` files.
    pub fn get_tunnels() -> Vec<ManagedTunnel> {
        use glob::glob;
        let cloudflared = home_dir()
            .expect("can not detect home directory")
            .join("/.cloudflared")
            .as_path()
            .as_os_str()
            .to_str()
            .expect("can not use the OS derived path")
            .to_string();
        let json_files = cloudflared.clone();
        json_files.push_str("/*.json");
        let yaml_files = cloudflared.clone();
        yaml_files.push_str("/*.y[a]{0,1}ml");
        debug!(
            "Glob pattern for currently managed tunnels:\n json:{:?},\n yaml:${:?}",
            &json_files, &yaml_files
        );

        let mut tunnels: Vec<ManagedTunnel> = vec![];

        // iterate over credentials files which have a 1:1 reln to managed tunnels
        for filename in glob(&json_files).expect("Failed to read glob pattern") {
            match filename {
                Ok(path) => {
                    debug!(
                        "[{}] getting file contents for tunnel ingress file",
                        path.display()
                    );
                    let data = fs::read_to_string(path);
                    debug!("[{}] tunnel ingress file read into memory", path.display());
                    match data {
                        Ok(data) => {
                            let credentials: CloudflareCredentials =
                                serde_json::from_str(&data).unwrap();
                            let filename = path.file_name().unwrap().to_string_lossy().to_string();
                            let tunnel = ManagedTunnel::new(&filename, &credentials);
                            let filename = cloudflared.clone();
                            filename.push_str(&tunnel.tunnel_id);

                            // transform ingress rules and fallback into `ManagedTunnel`
                            if let Some(file) = get_ingress_file(&filename) {
                                if file.ingress.len() > 0 {
                                    let last = file.ingress.pop().unwrap();
                                    match last {
                                        IngressFileRule::Rule(rule) => {
                                            // the whole stack is rules, no fallback
                                            // so just push back on stack
                                            file.ingress.push(IngressFileRule::Rule(rule));
                                        }
                                        IngressFileRule::Fallback(fallback) => {
                                            tunnel.ingress_fallback = fallback;
                                        }
                                    }
                                    for rule in file.ingress {
                                        match rule {
                                            IngressFileRule::Fallback(fb) => {
                                                error!("Multiple fallback rules found in ingress file {}. Will ignore the rule: {}", &filename, fb.service);
                                            }
                                            IngressFileRule::Rule(rule) => {
                                                tunnel.ingress_rules.push(rule);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "not able to successfully load the file '{}'",
                                path.display()
                            )
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Error trying to resolve a filename for item in glob pattern: {:?}",
                        e
                    );
                }
            }
        }

        tunnels
    }
}

#[derive(Serialize, Deserialize)]
pub struct CloudflareCli {
    /// The status of the Cloudflare certificate
    cert: CloudflareCert,
    /// The tunnel's which this server manages directly,
    /// including all ingress routes.
    managed_tunnels: Vec<ManagedTunnel>,
    /// flag indicating whether DNS forwarding is on
    dns: bool,
    /// The currently known set of tunnels setup with
    /// the Cloudflare account. This can include tunnels which
    /// are _external_ to this server's responsibilities.
    tunnels: Vec<Tunnel>,
    proxy_dashboard: Option<ProxyDashboard>,
}

impl CloudflareCli {
    pub fn new() -> CloudflareCli {
        let s = CloudflareCli {
            cert: CloudflareCert::get(),
            managed_tunnels: vec![],
            dns: match env::var("dns") {
                Ok(dns) => {
                    if dns == "false" {
                        false
                    } else {
                        true
                    }
                }
                Err(_) => false,
            },
            tunnels: vec![],
            proxy_dashboard: None,
        };

        if s.has_cert() {
            //
        }

        s
    }

    pub fn has_cert(&self) -> bool {
        self.cert.ready()
    }

    /// List all tunnels which Cloudflare is currently _aware of_
    /// and will update the "tunnels" property of the status passed
    /// in.
    ///
    /// In cases where we are not yet ready to call this function
    // #[instrument()]
    pub fn list_tunnels(&mut self) -> Result<Vec<Tunnel>> {
        // no cert, no go
        if !self.has_cert() {
            warn!("call to list_tunnels prior to there being a cert.pem file");
            self.tunnels = vec![];

            Err("not ready")
        }

        let cli = Command::new("cloudflared")
            .args(["tunnel", "list", "-o", "json"])
            .output();
        // cli successful
        if let Ok(cli) = cli {
            let stdout = String::from_utf8_lossy(&cli.stdout).clone();
            let stderr = String::from_utf8_lossy(&cli.stderr).clone();

            if !stdout.is_empty() {
                let tunnels = serde_json::from_str(&stdout);
                match tunnels {
                    Ok(tunnels) => tunnels,
                    Err(err) => {
                        error!("There was a problem parsing the stdout results gotten back from Cloudflare when requesting the LIST of tunnels: {}", err);
                    }
                }

                if tunnels.is_ok() {
                    // update own record of tunnels
                    self.tunnels = tunnels;
                    // and return
                    tunnels
                } else {
                    self.tunnels = TunnelStatus::ParseError()
                }
            }
        } else {
            warn!("The cert.pem file is not yet hosted by the docker volume")
        }

        todo!()
    }
}
