use std::collections::HashMap;

const COOKIE_ATTRIBUTES: &str = "Path=/; SameSite=Lax; Secure; HttpOnly";
const COOKIE_PREFIX: &str = "__Secure-";

pub fn parse(cookie_string: &str) -> HashMap<&str, &str> {
    cookie_string
        .split("; ")
        .filter_map(|kv| {
            kv.find('=').map(|index| {
                let (key, value) = kv.split_at(index);
                let mut key = key.trim();
                if key.starts_with(&COOKIE_PREFIX) {
                    key = &key[..(key.len() - COOKIE_PREFIX.len())];
                }
                let value = value[1..].trim();
                (key, value)
            })
        })
        .collect()
}

pub fn persistent(name: &str, value: &str, max_age: u32) -> String {
    format!(
        "{}-{}={}; Max-Age={}; {}",
        COOKIE_PREFIX, name, value, max_age, COOKIE_ATTRIBUTES
    )
}

pub fn expired(name: &str) -> String {
    persistent(name, "expired", 0)
}

pub fn session(name: &str, value: &str) -> String {
    format!(
        "{}-{}={}; {}",
        COOKIE_PREFIX, name, value, COOKIE_ATTRIBUTES
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::parse;

    #[test]
    fn parse_success() {
        struct Test {
            name: &'static str,
            cookie: &'static str,
            expected: HashMap <&'static str, &'static str>,
        }

        let test_cases = [
            Test {
                name: "empty cookie",
                cookie: "",
                expected: [
                ].iter().cloned().collect(),
            },
            Test {
                name: "a single value",
                cookie: "key1=val1",
                expected: [
                    ("key1", "val1"),
                ].iter().cloned().collect(),
            },
            Test {
                name: "two values",
                cookie: "key1=val1; key2=val2",
                expected: [
                  ("key1", "val1"),
                  ("key2", "val2")
                ].iter().cloned().collect(),
            }
        ];

        for test_case in test_cases.iter() {
            let res = parse(test_case.cookie.as_ref());

            assert_eq!(res.len(), test_case.expected.len(), "Test with '{}' failed", test_case.name);
            for (key, _) in res.iter() {
                assert_eq!(res[key], test_case.expected[key], "Test with '{}' failed", test_case.name);
            }

        }
    }
}