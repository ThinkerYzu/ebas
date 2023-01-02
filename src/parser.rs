use super::Program;

#[derive(Debug, PartialEq, Eq)]
pub enum LabelType {
    NoType,
    Func,
    Data,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Insn {
    // label_name, is_function
    Label(String, LabelType),
    Insn(String, String, isize, String, String, isize, String),
    Section(String),
    Bss(String),
    Dbytes(Vec<u8>),
    Dwords(Vec<u32>),
    Ddwords(Vec<u64>),
    None,
}

fn tokenize(line: &str) -> Result<Vec<&str>, ()> {
    let mut last_nows = 0;
    let mut tokens = vec![];
    let mut in_quote = false;

    for (off, c) in line.chars().enumerate() {
        if in_quote {
            if c == '"' {
                tokens.push(&line[last_nows..(off + 1)]);
                in_quote = false;
                last_nows = off + 1;
            }
            continue;
        }
        if c == '"' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }
            last_nows = off;
            in_quote = true;
            continue;
        }
        if c.is_whitespace() {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }
            last_nows = off + 1;
            continue;
        }
        if "+-.:,".contains(c) {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push(&line[off..(off + 1)]);
            last_nows = off + 1;
            continue;
        }
        if c == '/' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            if off < line.len() - 1 && &line[off + 1..off + 2] == "/" {
                return Ok(tokens);
            }
            return Err(());
        }
        if !c.is_ascii_alphanumeric() && c != '_' && (off != last_nows || c != '@') {
            return Err(());
        }
    }
    if in_quote {
        return Err(());
    }
    if last_nows != line.len() {
        tokens.push(&line[last_nows..]);
    }

    Ok(tokens)
}

#[derive(PartialEq, Debug, Eq)]
pub struct ParseError {
    pub line: String,
    pub reason: String,
    pub line_no: usize,
}

impl ParseError {
    pub fn new(line: &str, reason: &str) -> Result<Insn, ParseError> {
        Err(ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no: 0,
        })
    }

    pub fn new_prog(line_no: usize, line: &str, reason: &str) -> Result<Program, ParseError> {
        Err(ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no,
        })
    }

    pub fn new_p(line_no: usize, line: &str, reason: &str) -> ParseError {
        ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no,
        }
    }
}

pub fn parse_line(line: &str) -> Result<Insn, ParseError> {
    let mut tokens = tokenize(line).map_err(|_| ParseError::new_p(0, line, "tokenize error"))?;
    if tokens.is_empty() {
        return Ok(Insn::None);
    }

    if tokens[0] == "." {
        if tokens.len() < 2 {
            return ParseError::new(line, "invalid syntax");
        }
        match tokens[1] {
            "section" => {
                // section
                if tokens.len() != 3 {
                    ParseError::new(line, "need exact one section name")?;
                }
                let sect_name = if tokens[2].starts_with('\"') {
                    if !tokens[2].ends_with('\"') {
                        return ParseError::new(line, "missing quote (\")");
                    }
                    tokens[2]
                        .strip_prefix('\"')
                        .unwrap()
                        .strip_suffix('\"')
                        .unwrap()
                        .to_string()
                } else {
                    tokens[2].to_string()
                };
                Ok(Insn::Section(sect_name))
            }
            "bss" => {
                // section
                if tokens.len() != 3 {
                    if tokens.len() != 2 {
                        ParseError::new(line, "need exact one section name")?;
                    }
                    tokens.push("\".bss\"");
                }
                let sect_name = if tokens[2].starts_with('\"') {
                    if !tokens[2].ends_with('\"') {
                        return ParseError::new(line, "missing quote (\")");
                    }
                    tokens[2]
                        .strip_prefix('\"')
                        .unwrap()
                        .strip_suffix('\"')
                        .unwrap()
                        .to_string()
                } else {
                    tokens[2].to_string()
                };
                Ok(Insn::Bss(sect_name))
            }
            "function" => {
                if tokens.len() != 3 {
                    return ParseError::new(line, "need exact one function name");
                }
                let fname = tokens[2].to_string();
                Ok(Insn::Label(fname, LabelType::Func))
            }
            "data" => {
                if tokens.len() != 3 {
                    return ParseError::new(line, "need exact one data name");
                }
                let fname = tokens[2].to_string();
                Ok(Insn::Label(fname, LabelType::Data))
            }
            _ => ParseError::new(line, &format!("unknown keyword {}", tokens[1])),
        }
    } else if tokens.len() == 2 && tokens[1] == ":" {
        // label
        let label_name = tokens[0];
        Ok(Insn::Label(label_name.to_string(), LabelType::NoType))
    } else {
        match tokens[0] {
            "db" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u8::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse()
                                    .map_err(|_| ParseError::new_p(0, line, "invalid number"))?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Dbytes(values))
            }
            "dw" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u32::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse()
                                    .map_err(|_| ParseError::new_p(0, line, "invalid number"))?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Dwords(values))
            }
            "dd" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u64::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse().map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Ddwords(values))
            }
            _ => {
                // text section
                let mut cmd = tokens[0].to_string();
                if cmd == "exit" {
                    if tokens.len() != 1 {
                        return ParseError::new(line, "invalid syntax; unused operands");
                    }
                    return Ok(Insn::Insn(
                        cmd,
                        "".to_string(),
                        1,
                        0.to_string(),
                        "".to_string(),
                        1,
                        0.to_string(),
                    ));
                }

                let is_call = cmd == "call";
                while tokens.len() >= 3 && tokens[1] == "." {
                    cmd = format!("{}.{}", cmd, tokens[2]);
                    tokens.remove(1);
                    tokens.remove(1);
                }

                if is_call {
                    if tokens.len() != 2 {
                        return ParseError::new(line, "invalid number of operands");
                    }
                    return Ok(Insn::Insn(
                        cmd,
                        tokens[1].to_string(),
                        1,
                        0.to_string(),
                        "".to_string(),
                        1,
                        0.to_string(),
                    ));
                }

                let mut tidx = 1;
                let dst = tokens[tidx];
                tidx += 1;
                if tidx >= tokens.len() {
                    return ParseError::new(line, "invalid number of operands");
                }
                let (dst_sign, dst_off) = if tokens[tidx] == "+" || tokens[tidx] == "-" {
                    let sign: isize = if tokens[tidx] == "+" { 1 } else { -1 };
                    tidx += 1;
                    if tidx >= tokens.len() {
                        return ParseError::new(line, "incomplete line");
                    }
                    let v = tokens[tidx];
                    tidx += 1;
                    if tidx >= tokens.len() {
                        return ParseError::new(line, "incomplete line");
                    }
                    (sign, v)
                } else {
                    (1, "0")
                };
                if tokens[tidx] != "," {
                    return ParseError::new(
                        line,
                        &format!("expect a comma after {}", tokens[tidx - 1]),
                    );
                }
                tidx += 1;
                if tidx >= tokens.len() {
                    return ParseError::new(line, "expect one more operand");
                }

                let src = tokens[tidx];
                tidx += 1;
                let (src_sign, src_off) = if tidx < tokens.len()
                    && (tokens[tidx] == "+" || tokens[tidx] == "-" || tokens[tidx] == ",")
                {
                    if tokens[tidx] == "," {
                        // Support three operands syntax.  The
                        // third operand is always an offset. Like
                        // `jne r1, r2, 0x30`.
                        //
                        // Translate the reset tokens to the form,
                        // likes `jne r1, r2 + 0x30`.
                        if (tidx + 1) >= tokens.len() {
                            return ParseError::new(line, "invalid syntax");
                        }
                        if tokens[tidx + 1] != "+" && tokens[tidx + 1] != "-" {
                            tokens[tidx] = "+";
                        } else {
                            tokens.remove(tidx);
                        }
                    }

                    let sign: isize = if tokens[tidx] == "+" { 1 } else { -1 };
                    tidx += 1;
                    if tidx >= tokens.len() {
                        return ParseError::new(line, "invalid syntax");
                    }
                    let v = tokens[tidx];
                    tidx += 1;
                    (sign, v)
                } else {
                    (1, "0")
                };

                if tidx != tokens.len() {
                    return ParseError::new(line, "invalid syntax");
                }

                Ok(Insn::Insn(
                    cmd,
                    dst.to_string(),
                    dst_sign,
                    dst_off.to_string(),
                    src.to_string(),
                    src_sign,
                    src_off.to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        let r = parse_line("my_label:");
        assert_eq!(
            r,
            Ok(Insn::Label("my_label".to_string(), LabelType::NoType))
        );

        let r = parse_line(" my_label : // sfaf");
        assert_eq!(
            r,
            Ok(Insn::Label("my_label".to_string(), LabelType::NoType))
        );

        let r = parse_line(".section text");
        assert_eq!(r, Ok(Insn::Section("text".to_string())));

        let r = parse_line(" . section data //");
        assert_eq!(r, Ok(Insn::Section("data".to_string())));

        let r = parse_line(" . bss //");
        assert_eq!(r, Ok(Insn::Bss(".bss".to_string())));

        let r = parse_line(" . bss \"testbss\"//");
        assert_eq!(r, Ok(Insn::Bss("testbss".to_string())));

        let r = parse_line("db 33, 0x22 //foobar");
        assert_eq!(r, Ok(Insn::Dbytes(vec![33, 0x22])));

        let r = parse_line("dw 33,22");
        assert_eq!(r, Ok(Insn::Dwords(vec![33, 22])));

        let r = parse_line("dd 0x33 //");
        assert_eq!(r, Ok(Insn::Ddwords(vec![0x33])));

        let r = parse_line("jne r1, r2, -0x3");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "jne".to_string(),
                "r1".to_string(),
                1,
                "0".to_string(),
                "r2".to_string(),
                -1,
                "0x3".to_string(),
            ))
        );

        let r = parse_line("ld r3, 22 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "22".to_string(),
                1,
                "0".to_string(),
            ))
        );

        let r = parse_line("\tld r3,22 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "22".to_string(),
                1,
                "0".to_string(),
            ))
        );

        let r = parse_line("\tld r3,r4+7 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "r4".to_string(),
                1,
                7.to_string(),
            ))
        );

        let r = parse_line("\tld r3-7,r4 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                -1,
                7.to_string(),
                "r4".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line("\tld r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w.64 r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w.64".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w.64 r3 + 3,r4 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w.64".to_string(),
                "r3".to_string(),
                1,
                3.to_string(),
                "r4".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line(" call 0x33");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call".to_string(),
                "0x33".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string()
            ))
        );

        let r = parse_line(" call.helper 0x33");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call.helper".to_string(),
                "0x33".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string()
            ))
        );

        let r = parse_line(" call.helper @LAB");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call.helper".to_string(),
                "@LAB".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line(" call.helper L@LAB");
        assert!(r.is_err());

        let r = parse_line(" exit");
        assert!(r.is_ok());
    }
}
