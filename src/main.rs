use std::error::Error;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket};
use pnet::transport::{transport_channel, TransportChannelType};
use rand::RngCore;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

fn main() {
    connection_switch();
}

fn connection_switch() {
    println!("'server' or 'client'?");
    let input = get_user_input();

    if input == "server" {
        server().expect("Fatal error on server");
    } else if input == "client" {
        client().expect("Fatal error on client");
    } else {
        println!("Invalid entry");
    }
}

fn server() -> Result<(), Box<dyn Error>> {
    println!("--- SERVER MODE ---");
    println!("Input address to bind (e.g., 127.0.0.1:8080):");
    let address = get_address();

    let socket = UdpSocket::bind(&address)?;
    println!("Echo UDP server listening in: {}", address);

    loop {
        if let Err(e) = handle_client_message(&socket) {
            eprintln!("Error processing message: {}", e);
        }
    }
}

fn handle_client_message(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 1024];
    let (bytes_read, src_addr) = socket.recv_from(&mut buffer)?;
    let received_data = &buffer[..bytes_read];

    let message = std::str::from_utf8(received_data).unwrap_or("[non UTF-8 Data]");

    println!(
        "Received {} bytes from {}: {}",
        bytes_read,
        src_addr,
        message.trim_end()
    );

    socket.send_to(received_data, src_addr)?;
    Ok(())
}

fn client() -> Result<(), Box<dyn Error>> {
    println!("--- CLIENT MODE ---");

    println!("Input the server IP address (e.g., 127.0.0.1):");
    let target_ip: Ipv4Addr = get_address().parse()?;

    println!("Input the server port (e.g., 8080):");
    let target_port: u16 = get_address().parse()?;

    println!("\nClient ready. Every message sent is spoofed to a random ip address.");
    println!("(input 'exit' to quit)");

    loop {
        let message = get_message_from_user()?;
        if message == "exit" {
            println!("Exiting client.");
            break;
        }
        
        let spoofed_ip = generate_random_ipv4();

        if let Err(e) = spoofed_client_sender(target_ip, spoofed_ip, target_port, &message) {
            eprintln!("Error sending packet: {}", e);
            break;
        }
    }

    Ok(())
}

fn spoofed_client_sender(
    target_ip: Ipv4Addr,
    spoofed_src_ip: Ipv4Addr,
    target_port: u16,
    message: &str,
) -> Result<(), Box<dyn Error>> {
    let packet_buffer = build_full_packet(spoofed_src_ip, target_ip, target_port, message.as_bytes())?;

    let (mut tx, _) = transport_channel(4096, TransportChannelType::Layer3(IpNextHeaderProtocols::Udp))
        .map_err(|e| format!("Failed to create raw socket. Try running with admin privileges (sudo): {}", e))?;
    
    let ip_packet = Ipv4Packet::new(&packet_buffer).ok_or("Invalid packet buffer")?;
    tx.send_to(ip_packet, IpAddr::V4(target_ip))?;

    println!("Spoofed packet from {} sent to {}:{}", spoofed_src_ip, target_ip, target_port);

    Ok(())
}

fn build_full_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let packet_size = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let mut packet_buffer = vec![0u8; packet_size];

    {
        let mut udp_packet = MutableUdpPacket::new(&mut packet_buffer[IPV4_HEADER_LEN..])
            .ok_or("Buffer too small for UDP packet")?;
        
        let source_port = rand::thread_rng().next_u32() as u16;
        udp_packet.set_source(source_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length((UDP_HEADER_LEN + payload.len()) as u16);
        udp_packet.set_payload(payload);
        
        let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src_ip, &dst_ip);
        udp_packet.set_checksum(checksum);
    }

    {
        let mut ip_packet = MutableIpv4Packet::new(&mut packet_buffer)
            .ok_or("Buffer too small for IP packet")?;
        
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(packet_size as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);
        
        let checksum = ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);
    }
    
    Ok(packet_buffer)
}

fn generate_random_ipv4() -> Ipv4Addr {
    let mut octets = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut octets);
    Ipv4Addr::from(octets)
}

fn read_line_from_user() -> Result<String, io::Error> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer.trim().to_string())
}

fn get_message_from_user() -> Result<String, io::Error> {
    print!("> ");
    io::stdout().flush()?;
    read_line_from_user()
}

fn get_user_input() -> String {
    read_line_from_user().expect("Error reading input")
}

fn get_address() -> String {
    get_user_input()
}
