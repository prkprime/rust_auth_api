use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use bcrypt;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

lazy_static! {
    static ref DB: Mutex<UserDB> = Mutex::new(UserDB::new());
}

#[derive(Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct Msg {
    message: String,
}

#[derive(Clone)]
struct UserDB {
    users: Arc<Mutex<HashMap<String, String>>>,
}

impl UserDB {
    fn new() -> UserDB {
        UserDB {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn add_user(&mut self, username: String, password: String) -> bool {
        if !self.users.lock().unwrap().contains_key(&username) {
            self.users
                .lock()
                .unwrap()
                .insert(username, bcrypt::hash(password, 4).unwrap());
            true
        } else {
            false
        }
    }

    fn verify_user(&self, username: String, password: String) -> bool {
        match self.users.lock().unwrap().get(&username) {
            None => false,
            Some(hashed_password) => bcrypt::verify(password, hashed_password).unwrap(),
        }
    }
}

async fn login(user: web::Json<User>) -> impl Responder {
    if DB
        .lock()
        .unwrap()
        .verify_user(user.username.clone(), user.password.clone())
    {
        HttpResponse::Ok().json(Msg {
            message: String::from("Loged in successfully"),
        })
    } else {
        HttpResponse::Unauthorized().json(Msg {
            message: String::from("Wrong username or password"),
        })
    }
}

async fn register(user: web::Json<User>) -> impl Responder {
    if DB
        .lock()
        .unwrap()
        .add_user(user.username.clone(), user.password.clone())
    {
        HttpResponse::Ok().json(Msg {
            message: String::from("Registered successfully"),
        })
    } else {
        HttpResponse::Unauthorized().json(Msg {
            message: String::from("User already exists"),
        })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().service(
            web::scope("/api/v1")
                .route("/login", web::post().to(login))
                .route("/register", web::post().to(register)),
        )
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

#[cfg(test)]
mod user_db_tests {
    use super::*;

    fn create_dummy_user() -> UserDB {
        let mut new_user_db = UserDB::new();
        new_user_db.add_user(String::from("username"), String::from("password"));
        new_user_db
    }

    #[test]
    fn verify_with_correct_username_and_password() {
        assert!(create_dummy_user().verify_user(String::from("username"), String::from("password")));
    }

    #[test]
    fn verify_with_wrong_username() {
        assert!(
            !UserDB::new().verify_user(String::from("wrong_username"), String::from("password"))
        );
    }

    #[test]
    fn verify_with_wrong_password() {
        assert!(!create_dummy_user()
            .verify_user(String::from("username"), String::from("wrong_password")));
    }

    #[test]
    fn add_user() {
        assert!(UserDB::new().add_user(String::from("username"), String::from("password")));
    }

    #[test]
    fn add_duplicate_user() {
        assert!(!create_dummy_user().add_user(String::from("username"), String::from("password")));
    }
}
