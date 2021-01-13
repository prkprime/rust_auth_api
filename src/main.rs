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

    fn add_user(&mut self, username: String, password: String) {
        self.db
            .lock()
            .unwrap()
            .insert(username, bcrypt::hash(password, 4).unwrap());
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
mod tests {
    use super::*;

    fn create_dummy_user() -> UserDB {
        let mut new_user_db = UserDB::new();
        new_user_db.add_user(String::from("abcd"), String::from("abcd"));
        new_user_db
    }

    #[test]
    fn verify_correct_user() {
        assert!(create_dummy_user().verify_user(String::from("abcd"), String::from("abcd")));
    }

    #[test]
    fn no_user() {
        assert!(!UserDB::new().verify_user(String::from("abcde"), String::from("abcd")));
    }

    #[test]
    fn wrong_password() {
        assert!(!create_dummy_user().verify_user(String::from("abcd"), String::from("abcde")));
    }
}
