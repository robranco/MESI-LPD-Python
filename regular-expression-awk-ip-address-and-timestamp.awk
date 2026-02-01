#awk '
function ts_access(line,    a) {
  return (match(line, /\[[0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\]/, a) ? substr(line, RSTART, RLENGTH) : "")
}
function ts_apache(line,    a) {
  return (match(line, /\[[A-Za-z]{3} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{1,6} [0-9]{4}\]/, a) ? substr(line, RSTART, RLENGTH) : "")
}
function ts_syslog(line,    a) {
  return (match(line, /^[A-Za-z]{3}[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}/, a) ? substr(line, RSTART, RLENGTH) : "")
}
function get_ts(line,    t) {
  t = ts_access(line); if (t != "") return t
  t = ts_apache(line); if (t != "") return t
  t = ts_syslog(line); if (t != "") return t
  return ""
}

{
  ts = get_ts($0);
  if (ts == "") next

  # Access log: [IP]:PORT ...
  if (match($0, /^\[([0-9A-Fa-f:.]+)\]:[0-9]+/, a)) { print ts "\t" a[1]; next }

  # Apache error: [client IP:PORT] ... (strip trailing :PORT)
  if (match($0, /\[client ([0-9A-Fa-f:.]+)\]/, b)) {
    ip=b[1]; sub(/:[0-9]+$/, "", ip);
    print ts "\t" ip; next
  }

  # SSHD: "... from IP port N ..."
  if (match($0, /from ([0-9A-Fa-f:.]+) port [0-9]+/, c)) { print ts "\t" c[1]; next }

  # auth.log variants
  if (match($0, /rhost=([0-9A-Fa-f:.]+)/, d)) { print ts "\t" d[1]; next }
  if (match($0, /Received disconnect from ([0-9A-Fa-f:.]+):/, e)) { print ts "\t" e[1]; next }
  if (match($0, /Connection closed by ([0-9A-Fa-f:.]+)/, f)) { print ts "\t" f[1]; next }

  # UFW: print both SRC and DST (if present)
  if (match($0, /SRC=([0-9A-Fa-f:.]+)/, s)) { print ts "\t" s[1] }
  if (match($0, /DST=([0-9A-Fa-f:.]+)/, d2)) { print ts "\t" d2[1] }
}
#' /path/to/your/logfile
