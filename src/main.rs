use actix_web::{HttpMessage, HttpRequest ,  Error};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use futures::stream::StreamExt;
use mongodb::bson::doc;
use mongodb::Database;
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use argon2::{self, Config as ArgonConfig};
use uuid::Uuid;
use jsonwebtoken::{encode, Header, EncodingKey};
use std::env;
use rand::Rng; 

mod db;
mod models;
mod middleware;

#[derive(Debug, Serialize, Deserialize)]
struct Counter{
    _id: String,
    sequence: i64,
}

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

#[derive(Serialize, Deserialize)]
pub struct Todo{
    #[serde(rename = "_id")]
    id : i64,
    user_id : String,
    title: String,
    description : String,
    completed: bool,
}

async fn create_todo(db: web::Data<Collection<Todo>>, 
    todo : web::Json<Todo> , 
    req:HttpRequest  , 
    counter_db : web::Data<Collection<Counter>>) -> Result<HttpResponse , Error>{
        let next_id = get_next_id(&counter_db , "todo_id").await.map_err(actix_web::error::ErrorInternalServerError)?;
        let c_user_id = req.extensions().get::<String>().cloned();

        if let Some(user_id_g) =c_user_id{
            let new_todo = Todo{
                id: next_id,
                user_id: user_id_g,
                title: todo.title.clone(),
                description: todo.description.clone(),
                completed: todo.completed,
            };
            db.insert_one(new_todo, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
            Ok(HttpResponse::Created().json("Todo created successfully"))
        
        }
        else {
            Ok(HttpResponse::Unauthorized().body("Unauthorized , login first"))
        }

    }

async fn update_todo(db: web::Data<Collection<Todo>> ,
     req: HttpRequest,
     todo_id: web::Path<i64> ,
     new_value: web::Json<Todo>) -> Result <HttpResponse , Error>{

        let c_user_id = req.extensions().get::<String>().cloned();
        if let Some(user_id_g) = c_user_id{
            let filter = doc!{"_id": *todo_id , "user_id": user_id_g};

            if new_value.id != 0{
                Ok(HttpResponse::BadRequest().body("You cannot update the id of an existing todo."))
            }
            else{
                let new_todo = doc!{
                    "$set": {
                        "title": new_value.title.clone(),
                        "description": new_value.description.clone(),
                        "completed": new_value.completed,
                    }
                };
                let result = db.update_one(filter, new_todo , None).await.map_err(actix_web::error::ErrorInternalServerError)?;
                if result.modified_count == 1 {
                    Ok(HttpResponse::Ok().json("Todo updated successfully"))
                } else {
                    Ok(HttpResponse::NotFound().body("Todo not found"))
                }

            }

        }
        else {
            Ok(HttpResponse::Unauthorized().body("Unauthorized"))
        }

}

async fn get_next_id(db: &Collection<Counter> , seq_name: &str) -> Result<i64 , mongodb::error::Error>{

    let filter = doc!{"_id": seq_name};
    let update = doc!{"$inc":{seq_name: 1}};

    let options = mongodb::options::FindOneAndUpdateOptions::builder()
    .upsert(true).return_document(mongodb::options::ReturnDocument::After)
    .build();

    let result = db.find_one_and_update(filter , update , options).await?;
    
    if let Some(counter) = result{
        Ok(counter.sequence)
    }
    else {
        Err(mongodb::error::Error::custom("Failed to generate sequence value"))
    }


}

async fn get_todos(
    db: web::Data<Collection<Todo>>,
    req: HttpRequest
) -> Result<HttpResponse, Error> {
    let filter = doc!{"user_id": req.extensions().get::<String>().cloned()};
    let mut cursor = db.find(filter , None).await.map_err(actix_web::error::ErrorInternalServerError)?;
    let mut todos = vec![];
    while let Some(result) = cursor.next().await{
        match result {
            Ok(todo) => todos.push(todo),
            Err(e) => {
                eprintln!("Error fetching todo: {}", e);
                return Err(actix_web::error::ErrorInternalServerError("Failed to fetch todo"));
            }
        }
    }
    Ok(HttpResponse::Ok().json(todos))
}

async fn delete_todo(db: web::Data<Collection<Todo>> ,
    req: HttpRequest,
    todo_id: web::Path<i64>)->Result<HttpResponse , Error>{
        let c_user_id = req.extensions().get::<String>().cloned();
        if let Some(user_id_g) = c_user_id{
            let filter = doc!{"_id": *todo_id , "user_id": user_id_g};
            let result = db.delete_one(filter , None).await.map_err(actix_web::error::ErrorInternalServerError)?;
            if result.deleted_count == 1 {
                Ok(HttpResponse::Ok().json("Todo deleted successfully"))
            } else {
                Ok(HttpResponse::NotFound().body("Todo not found"))
            }
        }
        else{
            Ok(HttpResponse::Unauthorized().body("Unauthorized"))
        }
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
                    .route("/create_todo", web::post().to(create_todo))
                    .route("/update_todo", web::put().to(update_todo))
                    .route("/todos" , web::get().to(get_todos))
                    .route("/delete_todo/{id}", web::delete().to(delete_todo))
            )
    })
    .bind("127.0.0.1:8080")? // Bind the server to localhost on port 8080
    .run() // Run the server
    .await
}
