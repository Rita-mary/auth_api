use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use mongodb::bson::doc;
use mongodb::Database;
use serde::{Deserialize, Serialize};
use argon2::{self, Config as ArgonConfig};
use uuid::Uuid;
use jsonwebtoken::{encode, Header, EncodingKey};
use std::env;
use rand::Rng; // Added to resolve `.gen()` method error

mod db;
mod models;
mod middleware;

// Struct for sign-up input
#[derive(Debug,Deserialize)]
struct SignupInput {
    username: String,
    email: String,
    password: String,
}

// Struct for login input
#[derive(Deserialize)]
struct LoginInput {
    email: String,
    password: String,
}

// Struct for JWT claims (payload)
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (user ID)
    exp: usize,  // Expiration time as UTC timestamp
}

// Struct for authentication response
#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

// Handler for user sign-up
async fn sign_up(db: web::Data<Database>, input: web::Json<SignupInput>) -> impl Responder {
    println!("Received signup request: {:?}", input);
    let collection = db.collection::<models::User>("users");
    
    // Generate a random salt for Argon2
    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = ArgonConfig::default();
    
    // Hash the password
    let hashed_password = match argon2::hash_encoded(input.password.as_bytes(), &salt, &config) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return HttpResponse::InternalServerError().json("Internal Server Error");
        }
    };
    
    // Create a new user
    let new_user = models::User {
        id: Uuid::new_v4().to_string(),
        username: input.username.clone(),
        email: input.email.clone(),
        password: hashed_password,
    };
    
    // Insert the new user into MongoDB
    match collection.insert_one(new_user, None).await {
        Ok(_) => HttpResponse::Ok().json("User registered successfully"),
        Err(e) => {
            eprintln!("Failed to insert user: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

// Handler for user sign-in
async fn sign_in(db: web::Data<Database>, input: web::Json<LoginInput>) -> impl Responder {
    let collection = db.collection::<models::User>("users");
    
    // Find the user by email
    let user = collection.find_one(doc! { "email": &input.email }, None).await;
    
    match user {
        Ok(Some(user)) => {
            // Verify the password
            if argon2::verify_encoded(&user.password, input.password.as_bytes()).unwrap_or(false) {
                // Create JWT claims with an expiration time (1 hour)
                let expiration = chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::hours(1))
                    .expect("valid timestamp")
                    .timestamp() as usize;
                
                let claims = Claims {
                    sub: user.id.clone(),
                    exp: expiration,
                };
                
                // Retrieve the JWT secret from environment variables
                let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                
                // Encode the JWT
                let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Failed to encode token: {}", e);
                        return HttpResponse::InternalServerError().json("Internal Server Error");
                    }
                };
                
                // Respond with the JWT
                HttpResponse::Ok().json(AuthResponse { token })
            } else {
                // Password mismatch
                HttpResponse::Unauthorized().json("Invalid credentials")
            }
        },
        Ok(None) => {
            // User not found
            HttpResponse::Unauthorized().json("Invalid credentials")
        },
        Err(e) => {
            // Database error
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

// Handler to get user profile
async fn get_profile(db: web::Data<Database>, email: web::Path<String>) -> impl Responder {
    let collection = db.collection::<models::User>("users");
    
    // Find the user by email
    let user = collection.find_one(doc! { "email": &email.into_inner() }, None).await;
    
    match user {
        Ok(Some(user)) => {
            // Exclude the password before sending the user data
            let user_response = serde_json::json!({
                "id": user.id,
                "username": user.username,
                "email": user.email,
            });
            HttpResponse::Ok().json(user_response)
        },
        Ok(None) => {
            // User not found
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            // Database error
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

// Handler to update user profile
async fn update_profile(db: web::Data<Database>, email: web::Path<String>, input: web::Json<SignupInput>) -> impl Responder {
    let collection = db.collection::<models::User>("users");
    
    // Generate a random salt for Argon2
    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = ArgonConfig::default();
    
    // Hash the new password
    let hashed_password = match argon2::hash_encoded(input.password.as_bytes(), &salt, &config) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return HttpResponse::InternalServerError().json("Internal Server Error");
        }
    };
    
    // Prepare the update document
    let update = doc! {
        "$set": {
            "username": &input.username,
            "password": &hashed_password,
        }
    };
    
    // Execute the update operation
    match collection.update_one(doc! { "email": &email.into_inner() }, update, None).await {
        Ok(result) => {
            if result.matched_count == 1 {
                HttpResponse::Ok().json("Profile updated successfully")
            } else {
                HttpResponse::NotFound().json("User not found")
            }
        },
        Err(e) => {
            eprintln!("Failed to update user: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

// Handler to delete user profile
async fn delete_user(db: web::Data<Database>, email: web::Path<String>) -> impl Responder {
    let collection = db.collection::<models::User>("users");
    
    // Delete the user by email
    match collection.delete_one(doc! { "email": &email.into_inner() }, None).await {
        Ok(result) => {
            if result.deleted_count == 1 {
                HttpResponse::Ok().json("User deleted successfully")
            } else {
                HttpResponse::NotFound().json("User not found")
            }
        },
        Err(e) => {
            eprintln!("Failed to delete user: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok(); // Load environment variables from .env file
    env_logger::init(); // Initialize the logger
    
    // Connect to the MongoDB database
    let db = db::connect().await;
    
    // Retrieve the JWT secret from environment variables
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Start the Actix-web HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone())) // Share the database connection with handlers
            // Define public routes
            .route("/signup", web::post().to(sign_up))
            .route("/signin", web::post().to(sign_in))
            .service(
                web::scope("")
                    .wrap(middleware::AuthMiddleware::new(jwt_secret.clone()))
                    .route("/profile/{email}", web::get().to(get_profile))
                    .route("/profile/{email}", web::put().to(update_profile))
                    .route("/delete/{email}", web::delete().to(delete_user))
            )
    })
    .bind("127.0.0.1:8080")? // Bind the server to localhost on port 8080
    .run() // Run the server
    .await
}
