//! Plain-text tables and JSON for the command output.
use crate::error::{Exit, Result};
use serde::Serialize;

/// Left-aligned columns separated by two spaces; the last column is not padded.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    let render = |cells: Vec<&str>| {
        let last = cells.len().saturating_sub(1);
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate() {
            line.push_str(cell);
            if i < last {
                line.push_str(&" ".repeat(widths[i] - cell.chars().count() + 2));
            }
        }
        line.trim_end().to_owned()
    };
    let mut lines = vec![render(headers.to_vec())];
    lines.extend(
        rows.iter()
            .map(|row| render(row.iter().map(String::as_str).collect())),
    );
    lines.join("\n") + "\n"
}

pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value)
        .map(|s| s + "\n")
        .map_err(|e| Exit::api(format!("cannot render JSON: {e}")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn aligns_columns() {
        let out = super::table(
            &["NAME", "TYPE"],
            &[
                vec!["example.com".into(), "A".into()],
                vec!["a".into(), "TXT".into()],
            ],
        );
        assert_eq!(out, "NAME         TYPE\nexample.com  A\na            TXT\n");
    }
}
