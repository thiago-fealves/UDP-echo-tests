use std::io::{self, Write};
use std::net::UdpSocket;
use std::error::Error;

fn main() {
    connection_switch();
}

fn server() -> Result<(), Box<dyn Error>> {
    println!("--- SERVER MODE ---");
    println!("Input address to bind (e.g., 127.0.0.1:8080):");
    let address = get_address(); 
    
    let socket = bind_socket(&address)?;
    println!("Echo UDP server listening in: {}", address);

    loop {
        if let Err(e) = handle_client_message(&socket) {
            eprintln!("Error processing message: {}", e);
        }
    }
}

fn client() -> Result<(), Box<dyn Error>> {
    println!("--- CLIENT MODE ---");
    println!("Input the server address to connect to (e.g., 127.0.0.1:8080):");
    let server_address = get_address(); 
    
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    
    println!("Client ready, input your message and press enter");
    println!("   (input 'exit' to... i think you can figure it out yourself)");

    loop {
        let message = get_message_from_user()?;

        if message == "exit" {
            println!("Closing connection.");
            break;
        }

        if let Err(e) = send_message(&socket, &server_address, &message) {
            eprintln!("Connection Error: {}", e);
        }
    }

    Ok(())
}

/// The new, robust base function for reading a single line from stdin.
fn read_line_from_user() -> Result<String, io::Error> {
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(buffer.trim().to_string())
}

/// Prompts the user for a message and then reuses the base input function.
fn get_message_from_user() -> Result<String, io::Error> {
    print!("> ");
    io::stdout().flush()?;
    read_line_from_user()
}

/// A simple wrapper that panics on error, for use during initial setup.
fn get_user_input() -> String {
    read_line_from_user().expect("Error reading input")
}

/// Gets the address, unchanged in its call but now relies on the refactored logic.
fn get_address() -> String {
    get_user_input()
}

fn send_message(
    socket: &UdpSocket, 
    server_addr: &str, 
    message: &str
) -> Result<(), Box<dyn Error>> {
    
    socket.send_to(message.as_bytes(), server_addr)?;
    
    // Receiving reply
    let mut response_buffer = [0; 1024];
    let (bytes_read, _src_addr) = socket.recv_from(&mut response_buffer)?;
    
    // Printing reply
    let reply = std::str::from_utf8(&response_buffer[..bytes_read])?;
    println!("Server reply: {}", reply);
    
    Ok(())
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

fn bind_socket(address: &str) -> Result<UdpSocket, Box<dyn Error>> {
    let socket = UdpSocket::bind(address)?;
    Ok(socket)
}

fn handle_client_message(socket: &UdpSocket) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 1024];
    let (bytes_read, src_addr) = socket.recv_from(&mut buffer)?;
    let received_data = &buffer[..bytes_read];
    
    let message = std::str::from_utf8(received_data)
        .unwrap_or("[non UTF-8 Data]");
    
    println!("Received {} bytes from {}: {}", bytes_read, src_addr, message.trim_end());
    
    socket.send_to(received_data, src_addr)?;
    Ok(())
}
