# NSL-KDD Benchmark Dataset & Feature Representation Guide

## Dataset Background
The **NSL-KDD** dataset is a refined version of the classic KDD Cup 99 dataset, developed by the University of New Brunswick (Tavallaee et al., 2009) to address critical statistical deficiencies in the original KDD dataset (such as huge redundancy and duplicated records biasing classifier evaluations).

NSL-KDD contains 41 individual flow features plus a class label, categorizing network connections into **Normal** traffic and **4 Major Attack Families**.

---

## 4 Major Attack Families in NSL-KDD

### 1. Denial of Service (DoS)
- Attacks designed to shut down a machine or network, making it inaccessible to intended users.
- **Specific Attacks:** `neptune` (SYN flood), `smurf` (ICMP broadcast), `pod` (Ping of Death), `teardrop`, `land`, `back`, `apache2`, `udpstorm`.

### 2. Probe (Reconnaissance)
- Surveillance and probing of a network to gather information or discover vulnerabilities.
- **Specific Attacks:** `portsweep`, `ipsweep`, `satan`, `nmap`, `mscan`, `saint`.

### 3. Remote to Local (R2L)
- Unauthorized access from a remote machine attempting to gain local user privileges on the target system.
- **Specific Attacks:** `guess_passwd`, `ftp_write`, `imap`, `phf`, `multihop`, `warezmaster`, `spy`, `sendmail`.

### 4. User to Root (U2R)
- Local unprivileged user attempting to elevate privileges to root/administrator (privilege escalation).
- **Specific Attacks:** `buffer_overflow`, `rootkit`, `loadmodule`, `perl`, `ps`, `xterm`.

---

## 41 Flow Features Taxonomy

NSL-KDD features are organized into 4 distinct groups:

### 1. Basic Connection Features (Features 1 to 9)
- `duration`: Length of connection in seconds.
- `protocol_type`: Transport protocol (`tcp`, `udp`, `icmp`).
- `service`: Network service destination (`http`, `ftp`, `smtp`, `telnet`, `private`, `domain_u`, etc.).
- `flag`: Normal or error status of the connection (`SF` = normal establishment/termination, `S0` = SYN with no reply, `REJ` = connection rejected, `RSTO`/`RSTR` = reset).
- `src_bytes` & `dst_bytes`: Bytes sent from source to destination and vice versa.
- `land`: 1 if source and destination IP/ports are identical (Land attack spoofing); 0 otherwise.
- `wrong_fragment`: Number of incorrect fragment offsets.
- `urgent`: Number of urgent packets.

### 2. Content Features (Features 10 to 22) - Critical for R2L & U2R
- `hot`: Number of "hot" indicators (accessing system directories, execution of programs).
- `num_failed_logins`: Count of failed login attempts.
- `logged_in`: 1 if successfully logged in; 0 otherwise.
- `num_compromised`: Number of compromised conditions.
- `root_shell`: 1 if root shell obtained.
- `su_attempted`: 1 if `su root` command attempted.
- `num_root`: Number of root operations.
- `num_file_creations`, `num_shells`, `num_access_files`: System audit flags.

### 3. Time-based Traffic Features (Features 23 to 31)
- Window: Past 2 seconds.
- `count`: Number of connections to the same host as the current connection in past 2s.
- `srv_count`: Number of connections to the same service in past 2s.
- `serror_rate` & `srv_serror_rate`: Percentage of connections that activated SYN error flags.
- `rerror_rate` & `srv_rerror_rate`: Percentage of connections with REJ error flags.
- `same_srv_rate` & `diff_srv_rate`: Service similarity rates.

### 4. Host-based Traffic Features (Features 32 to 41)
- Window: Past 100 connections to the destination host.
- `dst_host_count`, `dst_host_srv_count`: Long-term host/service connection counts.
- `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`.
- `dst_host_serror_rate`, `dst_host_rerror_rate`.

---

## Machine Learning Interpretation in NetGuard AI
- **Flag Feature Importance:** The `flag` feature (`SF`, `S0`, `REJ`) is frequently one of the strongest predictive indicators for DoS and Probe detection.
- **Categorical Encoding:** `protocol_type`, `service`, and `flag` require One-Hot or Ordinal encoding before feeding into Scikit-learn Random Forest, Gradient Boosting, or Neural Network classifiers.
