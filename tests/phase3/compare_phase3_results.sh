#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <baseline_csv> <candidate_csv>"
  exit 1
fi

BASELINE_CSV="$1"
CANDIDATE_CSV="$2"

if [[ ! -f "$BASELINE_CSV" ]]; then
  echo "Baseline CSV not found: $BASELINE_CSV"
  exit 1
fi
if [[ ! -f "$CANDIDATE_CSV" ]]; then
  echo "Candidate CSV not found: $CANDIDATE_CSV"
  exit 1
fi

calc_stats() {
  local csv="$1"
  local metric="$2"
  awk -F, -v metric="$metric" '
    NR>1 && $2==metric {print $4}
  ' "$csv" | sort -n | awk '
    {
      vals[n++] = $1;
      sum += $1;
    }
    END {
      if (n == 0) {
        print "NA,NA,0";
        exit;
      }
      mean = sum / n;
      mid = int((n - 1) / 2);
      if (n % 2 == 1) {
        median = vals[mid];
      } else {
        median = (vals[mid] + vals[mid + 1]) / 2.0;
      }
      p95i = int((n - 1) * 0.95 + 0.5);
      if (p95i >= n) p95i = n - 1;
      p95 = vals[p95i];
      printf "%.3f,%.3f,%d\n", median, p95, n;
    }
  '
}

printf "metric,baseline_median_ms,candidate_median_ms,median_delta_pct,baseline_p95_ms,candidate_p95_ms,p95_delta_pct,samples\n"

for metric in \
  irelative_strict_fail_case \
  irelative_best_effort_case \
  irelative_execute_resolver_case
  do
  b_stats="$(calc_stats "$BASELINE_CSV" "$metric")"
  c_stats="$(calc_stats "$CANDIDATE_CSV" "$metric")"

  b_med="$(echo "$b_stats" | cut -d, -f1)"
  b_p95="$(echo "$b_stats" | cut -d, -f2)"
  b_n="$(echo "$b_stats" | cut -d, -f3)"

  c_med="$(echo "$c_stats" | cut -d, -f1)"
  c_p95="$(echo "$c_stats" | cut -d, -f2)"
  c_n="$(echo "$c_stats" | cut -d, -f3)"

  if [[ "$b_med" == "NA" || "$c_med" == "NA" ]]; then
    printf "%s,%s,%s,%s,%s,%s,%s,%s\n" "$metric" "$b_med" "$c_med" "NA" "$b_p95" "$c_p95" "NA" "0"
    continue
  fi

  delta_med="$(awk -v b="$b_med" -v c="$c_med" 'BEGIN { if (b==0) { print "NA" } else { printf "%.3f", ((c-b)/b)*100.0 } }')"
  delta_p95="$(awk -v b="$b_p95" -v c="$c_p95" 'BEGIN { if (b==0) { print "NA" } else { printf "%.3f", ((c-b)/b)*100.0 } }')"

  samples="$b_n"
  if [[ "$c_n" -lt "$b_n" ]]; then
    samples="$c_n"
  fi

  printf "%s,%.3f,%.3f,%s,%.3f,%.3f,%s,%s\n" "$metric" "$b_med" "$c_med" "$delta_med" "$b_p95" "$c_p95" "$delta_p95" "$samples"
done
