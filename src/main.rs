use std::io::Write;
use std::str::FromStr;
use std::env;
use std::io::{self};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;


const MAX_PORT_NUMER: u16 = 65535;


fn print_help(had_error: bool, error_message: &str) {
    match had_error {
        false => {
            println!("Port Sniffer by <xylian@xylian.org>");
            println!("The Port Sniffer prints the on-going port number of the target host.");
            println!("A test can be false negative if the target host does not response to it. So even if the port is open but no host is responding to it, the test will be negative.");
            println!("\n Usage:");
        },
        true => {
            println!("The usage of arguments has been entered wrong because {}. \nPlease follow the following usage:", error_message);
        }
    }
    println!("  -h or --help                    | this help message");
    println!("  -t IPADDRESS PORT               | tests if the entered port is open");
    println!("  -r IPADDRESS PORT_FROM PORT_TO  | tests if the range of ports is open");
    println!("  -a IPADDRESS THREADS_COUNT      | tests if the range of ports (1 - {}) is open", MAX_PORT_NUMER);
}

pub enum Flag {
    Simple, Target, Range, All
}

struct Arguments {
    flag: Flag,
    ipaddr: IpAddr,
    port_from: u16,
    port_to: u16,
    threads: u16
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("no arguments have been entered");
        }
        let f = args[1].clone();
        if let Ok(ipaddr) = IpAddr::from_str(&f) {
            return Ok(Arguments { flag: Flag::Simple, ipaddr, port_from: 1, port_to: MAX_PORT_NUMER, threads: 100 });
        } else {
            let flag = args[1].clone();
            if flag.contains("-h") || flag.contains("--help") {
                print_help(false, "");
                return Err("")
            } else if flag.contains("-t") || flag.contains("-r") || flag.contains("-a") {
                if args.len() == 2 { return Err("you must enter a IPADDRESS"); }
                let ipaddr = match IpAddr::from_str(&args[2]) {
                    Ok(s) => s,
                    Err(_) => return Err("IPADDRESS must be IPv4 or IPv6")
                };
                let port_from; let port_to; let threads; 

                if flag.contains("-a") {
                    if args.len() == 3 { return Err("you must enter a THREADS_COUNT"); }
                    threads = match args[3].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => return Err("THREADS_COUNT must be a number")
                    };
                    port_from = 1;
                    port_to = MAX_PORT_NUMER;
                    return Ok(Arguments {flag: Flag::All, ipaddr, port_from: port_from, port_to: port_to, threads});
                } else {
                    if args.len() == 3 { return Err("you must enter PORT_FROM"); }
                    port_from = match args[3].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => return Err("PORT_FROM must be a number")
                    };
                    
                    if flag.contains("-t") {
                        port_to = port_from;
                        threads = 1;
                        return Ok(Arguments {flag: Flag::Target, ipaddr, port_from: port_from, port_to: port_to, threads});
                    } else {
                        if args.len() == 4 { return Err("you must enter PORT_TO"); }
                        port_to = match args[4].parse::<u16>() {
                            Ok(s) => s,
                            Err(_) => return Err("PORT_FROM must be a number")
                        };
                        threads = port_to - port_from;
                    }
                    return Ok(Arguments {flag: Flag::Range, ipaddr, port_from: port_from, port_to: port_to, threads});
                }
            }
        }
        return Err("of invalid syntax")
    }
}

fn scan(tx: Sender<u16>, port_from: u16, port_to: u16, addr: IpAddr, threads_count: u16) {
    let mut port: u16 = port_from +1;
    loop {
        let stream = TcpStream::connect_timeout(&SocketAddr::new(addr, port), Duration::from_millis(200));
        match stream {
            Ok(_) => {
                print!("+");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            },
            Err(_) => {}
        }

        if (port_to - port) <= threads_count {
            break;
        }
        port += threads_count;
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err| {
            if err == "" {
                process::exit(0);
            } else {
                print_help(true, err);
                process::exit(1);
            }
        }
    );

    let flag = arguments.flag;
    let ipaddr = arguments.ipaddr;
    let port_from = arguments.port_from -1;
    let port_to = arguments.port_to;
    let threads_count = arguments.threads +port_from;
    let (tx, rx) = channel();
    for i in port_from..threads_count {
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, port_to, ipaddr, threads_count);
        });
    }

    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p)
    }

    print!("\n");
    match flag {
        Flag::Target => {
            let mut target_port_is_open: bool = false;
            for p in out {
                if p == arguments.port_from { target_port_is_open = true; }
            }
            if target_port_is_open {
                println!("Port {} is open", arguments.port_from);
            } else {
                println!("Port {} is NOT open", arguments.port_from);
            }
        }

        _ => {
            let mut count: u16 = 0;
            for p in out {
                count += 1;
                println!("Port {} is open", p);
            }
            if count == 0 {
                println!("\nNO MATCHES");
            } else {
                println!("\nFound {} open ports", count);
            }
        }
    }

}
