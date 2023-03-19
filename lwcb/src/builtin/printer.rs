use std::ffi::CString;

fn print<T>(fmt: &CString, val: T) {
    unsafe { libc::printf(fmt.as_ptr(), val) };
}

pub fn print_string(fmt: &CString, val: String) {
    let cstring = CString::new(val).unwrap();
    print(fmt, cstring.as_ptr());
}

pub fn print_number<T>(fmt: &CString, val: T) {
    print(fmt, val)
}

pub fn parse_fmt(fmt: String) -> Vec<CString> {
    let mut is_escape = false;
    let mut fmts = vec![];
    let mut pre = 0;
    for (i, c) in fmt.chars().enumerate() {
        if c == '\\' {
            is_escape = !is_escape;
            continue;
        }
        if !is_escape && c == '%' {
            if i == 0 {
                fmts.push(CString::new("").expect("Failed to create cstring"));
            } else {
                fmts.push(CString::new(&fmt[pre..i]).unwrap());
            }
            pre = i;
            continue;
        }
        is_escape = false;
    }

    fmts.push(CString::new(&fmt[pre..fmt.len()]).unwrap());
    fmts
}
