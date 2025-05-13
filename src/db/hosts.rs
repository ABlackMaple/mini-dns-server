use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, path::Path, time::Duration};

use tokio::{fs::File, io::{AsyncBufReadExt, BufReader}};

use tracing::{debug, info};
use crate::{db::Key, dns::types::{Rdata, RecordClass, RecordType, ResourceRecord}};

use super::Db;

/// Load hosts file into the database
/// # Arguments
/// - `db`: The database to load the hosts file into
/// - `path`: The path to the hosts file
/// - `ttl`: The time to live for the records
/// # Returns
/// - `Result<u32>`: The number of records loaded into the database
pub async fn load_hosts_into_db(db: &Db, path: &str, ttl: u32) -> crate::Result<u32> {
    let path = Path::new(path);
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut count = 0;


    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        if let Ok(ipv4) = parts[0].parse::<Ipv4Addr>() {
            // ipv4 address
            for &domain in &parts[1..] {
                if domain.starts_with('#') {
                    break;
                }

                let record = to_resource_record(domain, ttl, ipv4.into());
                let key = Key::new(domain.to_string(), RecordType::A);
                db.insert(key, vec![record], Some(Duration::from_secs(ttl as u64))).await;
                debug!("inserted {} -> {}", domain, ipv4);
                count += 1;
            }
        } else if let Ok(ipv6) = parts[0].parse::<Ipv6Addr>() {
            // ipv6 address
            for &domain in &parts[1..] {
                if domain.starts_with('#') {
                    break;
                }

                let record = to_resource_record(domain, ttl, ipv6.into());
                let key = Key::new(domain.to_string(), RecordType::AAAA);
                db.insert(key, vec![record], Some(Duration::from_secs(ttl as u64))).await;
                debug!("inserted {} -> {}", domain, ipv6);
                count += 1;
            }
        }
    }
    info!("Loaded {} entries from {}", count, path.display());

    Ok(count)
}

/// Convert an A or AAAA record to a ResourceRecord
/// # Arguments
/// - `domain`: The domain name
/// - `ttl`: The time to live for the record
/// - `ip`: The IP address
/// # Returns
/// - `ResourceRecord`: The resource record
fn to_resource_record(domain: &str, ttl: u32, ip: IpAddr) -> ResourceRecord {
    use RecordType::*;
    let (rtype, rdata) = match ip {
        IpAddr::V4(ipv4) => {
            (A, Rdata::A(ipv4))
        },
        IpAddr::V6(ipv6) => {
            (AAAA, Rdata::AAAA(ipv6))
        }
    };
    ResourceRecord {
        name: domain.to_string(),
        rtype,
        rclass: RecordClass::IN,
        ttl,
        rdata: rdata,
    }
}