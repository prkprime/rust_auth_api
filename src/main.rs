use bcrypt;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

struct UserDB {
    db: Arc<Mutex<HashMap<String, String>>>,
}

impl UserDB {
    fn new() -> UserDB {
        UserDB {
            db: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn add_user(&mut self, username: String, password: String) -> bool {
        if !self.db.lock().unwrap().contains_key(&username) {
            self.db
                .lock()
                .unwrap()
                .insert(username, bcrypt::hash(password, 4).unwrap());
            true
        } else {
            false
        }
    }

    fn verify_user(&self, username: String, password: String) -> bool {
        match self.db.lock().unwrap().get(&username) {
            None => false,
            Some(hashed_password) => bcrypt::verify(password, hashed_password).unwrap(),
        }
    }
}

fn main() {
    println!("Hello World!")
}

#[cfg(test)]
mod db_tests {
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
