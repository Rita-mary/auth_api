use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id")]
    pub id: String,           // Unique identifier (UUID)
    pub username: String,    // User's display name
    pub email: String,       // User's email (used for login)
    pub password: String,    // Hashed password
}
