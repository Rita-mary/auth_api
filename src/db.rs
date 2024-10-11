use mongodb::{Client, options::ClientOptions, Database};
use std::env;

pub async fn connect() -> Database {
    // Retrieve the MongoDB connection string from environment variables
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    // Parse the connection string into client options
    let client_options = ClientOptions::parse(&database_url)
        .await
        .expect("Failed to parse MongoDB connection string");
    
    // Initialize the MongoDB client
    let client = Client::with_options(client_options).expect("Failed to initialize MongoDB client");
    
    // Specify the database name to use
    client.database("auth_db") // You can change "auth_db" to your preferred database name
}
