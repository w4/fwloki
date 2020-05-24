use std::collections::HashMap;

use chrono::offset::TimeZone;
use chrono::{DateTime, Datelike, Utc};
use nom::{
    bytes::complete::{tag, take, take_till, take_until},
    IResult,
};

fn parse_month<'a>((i, s): (&'a str, &str)) -> IResult<&'a str, u32> {
    match s {
        "Jan" => Ok((i, 1)),
        "Feb" => Ok((i, 2)),
        "Mar" => Ok((i, 3)),
        "Apr" => Ok((i, 4)),
        "May" => Ok((i, 5)),
        "Jun" => Ok((i, 6)),
        "Jul" => Ok((i, 7)),
        "Aug" => Ok((i, 8)),
        "Sep" => Ok((i, 9)),
        "Oct" => Ok((i, 10)),
        "Nov" => Ok((i, 11)),
        "Dec" => Ok((i, 12)),
        _ => Err(nom::Err::Failure(nom::error_position!(
            "Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec",
            nom::error::ErrorKind::OneOf
        ))),
    }
}

fn take_n_digits(i: &str, n: usize) -> IResult<&str, u32> {
    let (i, digits) = take(n)(i)?;

    match digits.parse() {
        Ok(res) => Ok((i, res)),
        Err(_) => Err(nom::Err::Failure(nom::error_position!(
            "Invalid string, expected ASCII representation of a number",
            nom::error::ErrorKind::Digit
        ))),
    }
}

fn parse_date_time(i: &str) -> IResult<&str, DateTime<Utc>> {
    let (i, month) = parse_month(take(3_usize)(i)?)?;
    let (i, _) = tag(" ")(i)?;
    let (i, day) = take_n_digits(i, 2)?;
    let (i, _) = tag(" ")(i)?;
    let (i, hour) = take_n_digits(i, 2)?;
    let (i, _) = tag(":")(i)?;
    let (i, min) = take_n_digits(i, 2)?;
    let (i, _) = tag(":")(i)?;
    let (i, sec) = take_n_digits(i, 2)?;
    Ok((
        i,
        chrono::Utc
            .ymd(chrono::Utc::today().year(), month, day)
            .and_hms(hour, min, sec),
    ))
}

fn parse_hostname(i: &str) -> IResult<&str, &str> {
    take_until(" ")(i)
}

fn parse_bracketed_param(i: &str) -> IResult<&str, &str> {
    let (i, _) = tag("[")(i)?;
    let (i, time) = take_until("]")(i)?;
    let (i, _) = tag("]")(i)?;

    Ok((i, time))
}

fn parse_kvs(i: &str) -> IResult<&str, HashMap<&str, &str>> {
    let (i, kvs) = nom::multi::separated_list0(
        nom::character::complete::char(' '),
        nom::sequence::separated_pair(take_until("="), tag("="), take_till(|c| c == ' ')),
    )(i)?;

    let mut map = HashMap::new();
    for (key, value) in kvs {
        map.insert(key, value);
    }

    Ok((i, map))
}

pub fn parse_log_line(i: &str) -> IResult<&str, Log> {
    let (i, time) = parse_date_time(i)?;
    let (i, _) = tag(" ")(i)?;
    let (i, hostname) = parse_hostname(i)?;
    let (i, _) = tag(" kernel: ")(i)?;
    let (i, _) = parse_bracketed_param(i)?; // kernel time
    let (i, _) = tag(" ")(i)?;
    let (i, rule) = parse_bracketed_param(i)?;
    let (i, values) = parse_kvs(i)?;

    Ok((
        i,
        Log {
            time,
            hostname,
            rule,
            values,
        },
    ))
}

#[derive(Debug)]
pub struct Log<'a> {
    pub hostname: &'a str,
    pub time: DateTime<Utc>,
    pub rule: &'a str,
    pub values: HashMap<&'a str, &'a str>,
}

#[cfg(test)]
mod tests {
    use chrono::Datelike;
    use chrono::Timelike;

    use crate::parser::parse_date_time;
    use crate::parser::parse_hostname;
    use crate::parser::parse_log_line;

    #[test]
    fn test_parse_date_time() {
        let (_, parsed) = parse_date_time("Apr 19 12:31:53").unwrap();
        assert_eq!(
            parsed.to_rfc3339(),
            format!("{}-04-19T12:31:53+00:00", chrono::Utc::today().year())
        );
    }

    #[test]
    fn test_parse_hostname() {
        let (_, parsed) = parse_hostname("vyos ignore the rest of this").unwrap();
        assert_eq!(parsed, "vyos");
    }

    #[test]
    fn test_parse_log_line() {
        let (rest, parsed) = parse_log_line("May 23 12:31:53 vyos kernel: [213370.255870] [OUTSIDE-LOCAL-default-D]IN=pppoe0 OUT= MAC= SRC=125.166.96.62 DST=80.80.80.80 LEN=143 TOS=0x00 PREC=0x00 TTL=110 ID=9398 PROTO=UDP SPT=1025 DPT=7140 LEN=123").unwrap();
        assert_eq!(parsed.time.hour(), 12);
        assert_eq!(parsed.hostname, "vyos");
        assert_eq!(parsed.rule, "OUTSIDE-LOCAL-default-D");
        assert_eq!(parsed.values.get("IN"), Some(&"pppoe0"));
        assert_eq!(parsed.values.get("MAC"), Some(&""));
        assert_eq!(parsed.values.get("DST"), Some(&"80.80.80.80"));
        assert_eq!(rest, "");
    }
}
