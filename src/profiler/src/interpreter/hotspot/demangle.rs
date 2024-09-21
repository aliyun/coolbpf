/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

use std::usize;

const JAVA_BASE_TYPES: &[(&str, char)] = &[
    ("byte", 'B'),
    ("char", 'C'),
    ("double", 'D'),
    ("float", 'F'),
    ("int", 'I'),
    ("long", 'J'),
    ("short", 'S'),
    ("void", 'V'),
    ("boolean", 'Z'),
];

fn demangle_java_type_signature<'a>(signature: &'a str, writer: &mut String) -> &'a str {
    let mut i = 0;
    let mut num_arr = 0;
    while i < signature.len() && signature.as_bytes()[i] == b'[' {
        num_arr += 1;
        i += 1;
    }
    if i >= signature.len() {
        return "";
    }

    let type_char = signature.as_bytes()[i];
    i += 1;

    if type_char == b'L' {
        let end = if let Some(end) = signature.find(';') {
            end
        } else {
            return "";
        };
        writer.push_str(&signature[i..end].replace('/', "."));
        i = end + 1;
    } else if let Some(&(type_str, _)) = JAVA_BASE_TYPES.iter().find(|(_, c)| *c as u8 == type_char)
    {
        writer.push_str(type_str);
    }

    for _ in 0..num_arr {
        writer.push_str("[]");
    }

    if signature.len() > i {
        return &signature[i..];
    }

    return "";
}

pub fn demangle_java_method(klass: &str, method: &str, signature: &str) -> String {
    let mut builder = String::new();

    let end = signature.find(')').unwrap_or(usize::MAX);

    if end != usize::MAX && signature.starts_with('(') {
        let mut left = &signature[end + 1..];
        left = demangle_java_type_signature(left, &mut builder);

        if left.len() != 0 {
            return String::new();
        }

        builder.push(' ');
        builder.push_str(&klass.replace('/', "."));
        builder.push('.');
        builder.push_str(method);
        builder.push('(');
        left = &signature[1..end];
        while !left.is_empty() {
            left = demangle_java_type_signature(left, &mut builder);
            if left.is_empty() {
                break;
            }
            builder.push_str(", ");
        }
        builder.push(')');
    }
    builder
}

pub fn demangle_java_method2(klass: &str, method: &str) -> String {
    let mut builder = String::new();
    builder.push_str(&klass.replace('/', "."));
    builder.push('.');
    builder.push_str(method);
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_java_demangling() {
        let cases = vec![
            ("java/lang/Object", "<init>", "()V", "void java.lang.Object.<init>()"),
            ("java/lang/StringLatin1", "equals", "([B[B)Z", "boolean java.lang.StringLatin1.equals(byte[], byte[])"),
            ("java/util/zip/ZipUtils", "CENSIZ", "([BI)J", "long java.util.zip.ZipUtils.CENSIZ(byte[], int)"),
            ("java/util/regex/Pattern$BmpCharProperty", "match", "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z", "boolean java.util.regex.Pattern$BmpCharProperty.match(java.util.regex.Matcher, int, java.lang.CharSequence)"),
            ("java/lang/AbstractStringBuilder", "appendChars", "(Ljava/lang/String;II)V", "void java.lang.AbstractStringBuilder.appendChars(java.lang.String, int, int)"),
            ("foo/test", "bar", "([)J", "long foo.test.bar()"),
        ];

        for (klass, method, signature, expected) in cases {
            let demangled = demangle_java_method(klass, method, signature);
            assert_eq!(expected, demangled);
        }
    }

    #[test]
    fn test_java_demangling2() {
        let cases = vec![
            (
                "java/lang/Object",
                "<init>",
                "()V",
                "java.lang.Object.<init>",
            ),
            (
                "java/lang/StringLatin1",
                "equals",
                "([B[B)Z",
                "java.lang.StringLatin1.equals",
            ),
            (
                "java/util/zip/ZipUtils",
                "CENSIZ",
                "([BI)J",
                "java.util.zip.ZipUtils.CENSIZ",
            ),
            (
                "java/util/regex/Pattern$BmpCharProperty",
                "match",
                "(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z",
                "java.util.regex.Pattern$BmpCharProperty.match",
            ),
            (
                "java/lang/AbstractStringBuilder",
                "appendChars",
                "(Ljava/lang/String;II)V",
                "java.lang.AbstractStringBuilder.appendChars",
            ),
            ("foo/test", "bar", "([)J", "foo.test.bar"),
        ];

        for (klass, method, _signature, expected) in cases {
            let demangled = demangle_java_method2(klass, method);
            assert_eq!(expected, demangled);
        }
    }
}
