use std::collections::BTreeSet;
use std::process::Command;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{BatmanError, BatmanResult};

#[derive(Clone, Debug)]
pub struct CronSchedule {
    seconds: Field,
    minutes: Field,
    hours: Field,
    days: Field,
    months: Field,
    weekdays: Field,
}

#[derive(Clone, Debug)]
struct Field {
    any: bool,
    values: BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DateParts {
    pub second: u32,
    pub minute: u32,
    pub hour: u32,
    pub day: u32,
    pub month: u32,
    pub weekday: u32,
}

impl CronSchedule {
    pub fn parse(expression: &str) -> BatmanResult<Self> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        let fields = match fields.as_slice() {
            [minute, hour, day, month, weekday] => {
                vec!["0", *minute, *hour, *day, *month, *weekday]
            }
            [second, minute, hour, day, month, weekday] => {
                vec![*second, *minute, *hour, *day, *month, *weekday]
            }
            _ => {
                return Err(BatmanError::Parse(format!(
                    "cron schedule must have 5 or 6 fields: {expression}"
                )));
            }
        };

        Ok(Self {
            seconds: Field::parse(fields[0], 0, 59)?,
            minutes: Field::parse(fields[1], 0, 59)?,
            hours: Field::parse(fields[2], 0, 23)?,
            days: Field::parse(fields[3], 1, 31)?,
            months: Field::parse(fields[4], 1, 12)?,
            weekdays: Field::parse(fields[5], 0, 7)?,
        })
    }

    pub fn should_run_at(&self, parts: DateParts) -> bool {
        self.seconds.matches(parts.second)
            && self.minutes.matches(parts.minute)
            && self.hours.matches(parts.hour)
            && self.days.matches(parts.day)
            && self.months.matches(parts.month)
            && weekday_matches(&self.weekdays, parts.weekday)
    }

    pub fn should_run_now(&self) -> bool {
        self.should_run_at(DateParts::now_local())
    }
}

impl Field {
    fn parse(raw: &str, min: u32, max: u32) -> BatmanResult<Self> {
        let mut values = BTreeSet::new();
        for item in raw.split(',') {
            parse_item(item, min, max, raw, &mut values)?;
        }
        Ok(Self {
            any: values.len() == (max - min + 1) as usize,
            values,
        })
    }

    fn matches(&self, value: u32) -> bool {
        self.any || self.values.contains(&value)
    }
}

fn parse_item(
    item: &str,
    min: u32,
    max: u32,
    raw: &str,
    values: &mut BTreeSet<u32>,
) -> BatmanResult<()> {
    let (range, step) = match item.split_once('/') {
        Some((range, step)) => {
            let step = step
                .parse::<u32>()
                .map_err(|_| BatmanError::Parse(format!("invalid cron field {raw}")))?;
            if step == 0 {
                return Err(BatmanError::Parse(format!("invalid zero step in {raw}")));
            }
            (range, step)
        }
        None => (item, 1),
    };

    let (start, end) = if range == "*" {
        (min, max)
    } else if let Some((start, end)) = range.split_once('-') {
        (
            parse_value(start, min, max, raw)?,
            parse_value(end, min, max, raw)?,
        )
    } else {
        let value = parse_value(range, min, max, raw)?;
        (value, value)
    };

    if start > end {
        return Err(BatmanError::Parse(format!(
            "invalid descending range {range}"
        )));
    }

    let mut value = start;
    while value <= end {
        values.insert(value);
        match value.checked_add(step) {
            Some(next) => value = next,
            None => break,
        }
    }
    Ok(())
}

fn parse_value(value: &str, min: u32, max: u32, raw: &str) -> BatmanResult<u32> {
    let value = value
        .parse::<u32>()
        .map_err(|_| BatmanError::Parse(format!("invalid cron field {raw}")))?;
    if value < min || value > max {
        return Err(BatmanError::Parse(format!(
            "cron value {value} outside {min}-{max}"
        )));
    }
    Ok(value)
}

impl DateParts {
    pub fn now_local() -> Self {
        Command::new("date")
            .arg("+%S %M %H %d %m %w")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                str::from_utf8(&output.stdout)
                    .ok()
                    .and_then(Self::from_local_date_output)
            })
            .unwrap_or_else(Self::now_utc)
    }

    pub fn now_utc() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        Self::from_unix_utc(seconds)
    }

    pub fn from_unix_utc(timestamp: i64) -> Self {
        let days = timestamp.div_euclid(86_400);
        let seconds_of_day = timestamp.rem_euclid(86_400) as u32;
        let (year, month, day) = civil_from_days(days);
        let _year = year;
        Self {
            second: seconds_of_day % 60,
            minute: (seconds_of_day / 60) % 60,
            hour: seconds_of_day / 3_600,
            day,
            month,
            weekday: unix_weekday(days),
        }
    }

    fn from_local_date_output(output: &str) -> Option<Self> {
        let mut parts = output.split_whitespace();
        let second = parts.next()?.parse().ok()?;
        let minute = parts.next()?.parse().ok()?;
        let hour = parts.next()?.parse().ok()?;
        let day = parts.next()?.parse().ok()?;
        let month = parts.next()?.parse().ok()?;
        let weekday = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            second,
            minute,
            hour,
            day,
            month,
            weekday,
        })
    }
}

fn weekday_matches(field: &Field, weekday: u32) -> bool {
    field.any || field.values.contains(&weekday) || (weekday == 0 && field.values.contains(&7))
}

fn unix_weekday(days_since_epoch: i64) -> u32 {
    ((days_since_epoch + 4).rem_euclid(7)) as u32
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::{CronSchedule, DateParts};

    #[test]
    fn parses_five_field_schedule_with_zero_seconds() {
        let schedule = CronSchedule::parse("30 22 * * *").unwrap();
        assert!(schedule.should_run_at(DateParts {
            second: 0,
            minute: 30,
            hour: 22,
            day: 1,
            month: 1,
            weekday: 1,
        }));
        assert!(!schedule.should_run_at(DateParts {
            second: 1,
            minute: 30,
            hour: 22,
            day: 1,
            month: 1,
            weekday: 1,
        }));
    }

    #[test]
    fn parses_six_field_schedule() {
        let schedule = CronSchedule::parse("0 30 22 * * *").unwrap();
        assert!(schedule.should_run_at(DateParts {
            second: 0,
            minute: 30,
            hour: 22,
            day: 2,
            month: 6,
            weekday: 3,
        }));
    }

    #[test]
    fn parses_ranges_lists_and_steps() {
        let schedule = CronSchedule::parse("0 */15 1-5 * * 1,3,5").unwrap();
        assert!(schedule.should_run_at(DateParts {
            second: 0,
            minute: 30,
            hour: 3,
            day: 10,
            month: 7,
            weekday: 3,
        }));
        assert!(!schedule.should_run_at(DateParts {
            second: 0,
            minute: 31,
            hour: 3,
            day: 10,
            month: 7,
            weekday: 3,
        }));
        assert!(!schedule.should_run_at(DateParts {
            second: 0,
            minute: 30,
            hour: 6,
            day: 10,
            month: 7,
            weekday: 3,
        }));
        assert!(!schedule.should_run_at(DateParts {
            second: 0,
            minute: 30,
            hour: 3,
            day: 10,
            month: 7,
            weekday: 2,
        }));
    }

    #[test]
    fn parses_range_steps() {
        let schedule = CronSchedule::parse("0 0 2-10/4 * * *").unwrap();
        assert!(schedule.should_run_at(DateParts {
            second: 0,
            minute: 0,
            hour: 6,
            day: 10,
            month: 7,
            weekday: 2,
        }));
        assert!(!schedule.should_run_at(DateParts {
            second: 0,
            minute: 0,
            hour: 8,
            day: 10,
            month: 7,
            weekday: 2,
        }));
    }

    #[test]
    fn parses_local_date_command_output() {
        assert_eq!(
            DateParts::from_local_date_output("05 04 03 02 01 6\n"),
            Some(DateParts {
                second: 5,
                minute: 4,
                hour: 3,
                day: 2,
                month: 1,
                weekday: 6,
            })
        );
        assert_eq!(DateParts::from_local_date_output("05 04 03"), None);
    }
}
