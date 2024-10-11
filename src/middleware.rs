use actix_web::{dev::ServiceRequest, Error};
use actix_web::error::ErrorUnauthorized;
use actix_web::dev::Transform;
use actix_service::{Service, forward_ready};
use actix_web::HttpMessage; // Added to bring `extensions_mut` into scope
use futures::future::{ok, Ready, LocalBoxFuture};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::rc::Rc;

// Define the Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (user ID)
    exp: usize,  // Expiration time as UTC timestamp
}

// Middleware factory
pub struct AuthMiddleware {
    secret: String,
}

impl AuthMiddleware {
    pub fn new(secret: String) -> Self {
        AuthMiddleware { secret }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddlewareMiddleware<S>;
    type InitError = ();

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareMiddleware {
            service: Rc::new(service),
            secret: self.secret.clone(),
        })
    }
}

pub struct AuthMiddlewareMiddleware<S> {
    service: Rc<S>,
    secret: String,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareMiddleware<S>
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let secret = self.secret.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Extract the Authorization header
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = &auth_str[7..];
                        
                        // Decode the token
                        match decode::<Claims>(
                            token,
                            &DecodingKey::from_secret(secret.as_ref()),
                            &Validation::new(Algorithm::HS256),
                        ) {
                            Ok(token_data) => {
                                // Token is valid; proceed to the next service
                                req.extensions_mut().insert(token_data.claims);
                                service.call(req).await
                            },
                            Err(_) => {
                                // Token is invalid
                                Err(ErrorUnauthorized("Invalid token"))
                            }
                        }
                    } else {
                        // Authorization header does not start with "Bearer "
                        Err(ErrorUnauthorized("Invalid authorization scheme"))
                    }
                } else {
                    // Authorization header is not a valid string
                    Err(ErrorUnauthorized("Invalid authorization header"))
                }
            } else {
                // No Authorization header found
                Err(ErrorUnauthorized("Authorization header missing"))
            }
        })
    }
}
